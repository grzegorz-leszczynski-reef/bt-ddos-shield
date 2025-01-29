import asyncio
import functools
from dataclasses import dataclass

from bt_ddos_shield.event_processor import PrintingMinerShieldEventProcessor, AbstractMinerShieldEventProcessor
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
from typing import Optional

import bittensor

from bt_ddos_shield.blockchain_manager import (
    AbstractBlockchainManager,
    ReadOnlyBittensorBlockchainManager,
)
from bt_ddos_shield.encryption_manager import AbstractEncryptionManager, ECIESEncryptionManager
from bt_ddos_shield.manifest_manager import (
    AbstractManifestManager,
    AbstractManifestSerializer,
    JsonManifestSerializer,
    Manifest,
    ReadOnlyS3ManifestManager,
)
from bt_ddos_shield.utils import Hotkey, PrivateKey


@dataclass
class ValidatorOptions:
    retry_delay_sec: int = 10
    """ Time in seconds to wait before retrying fetching miner address. """


class Validator:
    """
    Validator class used to retrieve address of miner shielded by MinerShield.
    """

    _validator_hotkey: Hotkey
    _validator_private_key: PrivateKey
    _blockchain_manager: AbstractBlockchainManager
    _manifest_manager: AbstractManifestManager
    _options: ValidatorOptions

    def __init__(self, validator_hotkey: Hotkey, validator_private_key: PrivateKey,
                 blockchain_manager: AbstractBlockchainManager, manifest_manager: AbstractManifestManager,
                 options: ValidatorOptions):
        self._validator_hotkey = validator_hotkey
        self._validator_private_key = validator_private_key
        self._blockchain_manager = blockchain_manager
        self._manifest_manager = manifest_manager
        self._options = options

    async def fetch_miner_address(self) -> str:
        while True:
            miner_manifest_url: Optional[str] = self._blockchain_manager.get_miner_manifest_address()
            if miner_manifest_url is not None:
                break

            await asyncio.sleep(self._options.retry_delay_sec)

        manifest: Manifest = self._manifest_manager.get_manifest(miner_manifest_url)
        url: str = self._manifest_manager.get_address_for_validator(manifest, self._validator_hotkey,
                                                                    self._validator_private_key)
        return url


class ValidatorFactoryException(Exception):
    pass


class SubtensorSettings(BaseModel):
    network: Optional[str] = None

    @functools.cached_property
    def client(self) -> bittensor.Subtensor:
        return bittensor.Subtensor(
            **self.model_dump()
        )


class ValidatorSettings(BaseSettings):
    miner_hotkey: str = Field(min_length=1)
    """Hotkey of shielded miner"""
    validator_hotkey: str = Field(min_length=1)
    """Hotkey of validator"""
    validator_private_key: str = Field(min_length=1)
    """Hex representation of secp256k1 private key of validator"""

    netuid: int
    subtensor: SubtensorSettings = SubtensorSettings()

    model_config = {
        'env_file': '.env',
        'env_nested_delimiter': '__',
    }


class ValidatorFactory:
    """
    Factory class to create proper Validator instance basing on set environmental variables.
    """

    @classmethod
    def create_validator(cls, settings: ValidatorSettings) -> Validator:
        event_processor: AbstractMinerShieldEventProcessor = cls.create_event_processor()
        encryption_manager: AbstractEncryptionManager = cls.create_encryption_manager()
        manifest_manager: AbstractManifestManager = cls.create_manifest_manager(encryption_manager)
        blockchain_manager: AbstractBlockchainManager = cls.create_blockchain_manager(settings, event_processor)
        options: ValidatorOptions = ValidatorOptions()
        return Validator(settings.validator_hotkey, settings.validator_private_key, blockchain_manager,
                         manifest_manager, options)

    @classmethod
    def create_event_processor(cls) -> AbstractMinerShieldEventProcessor:
        return PrintingMinerShieldEventProcessor()

    @classmethod
    def create_encryption_manager(cls) -> AbstractEncryptionManager:
        return ECIESEncryptionManager()

    @classmethod
    def create_manifest_manager(cls, encryption_manager: AbstractEncryptionManager) -> AbstractManifestManager:
        manifest_serializer: AbstractManifestSerializer = JsonManifestSerializer()
        return ReadOnlyS3ManifestManager(manifest_serializer, encryption_manager)

    @classmethod
    def create_blockchain_manager(
        cls,
        settings: ValidatorSettings,
        event_processor: AbstractMinerShieldEventProcessor,
    ) -> AbstractBlockchainManager:
        return ReadOnlyBittensorBlockchainManager(
            hotkey=settings.miner_hotkey,
            netuid=settings.netuid,
            subtensor=settings.subtensor.client,
            event_processor=event_processor
        )
