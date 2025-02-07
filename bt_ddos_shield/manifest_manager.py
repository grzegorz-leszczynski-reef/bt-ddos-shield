import asyncio
import base64
import functools
import hashlib
import httpx
import json

from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from http import HTTPStatus
from types import MappingProxyType
from typing import Any, Dict, Optional

from botocore.client import BaseClient
from bt_ddos_shield.address import (
    Address,
)
from bt_ddos_shield.encryption_manager import AbstractEncryptionManager
from bt_ddos_shield.event_processor import AbstractMinerShieldEventProcessor
from bt_ddos_shield.utils import AWSClientFactory, Hotkey, PrivateKey, PublicKey


class ManifestManagerException(Exception):
    pass


class ManifestDeserializationException(ManifestManagerException):
    """
    Exception thrown when deserialization of manifest data fails.
    """
    pass


class ManifestDownloadException(ManifestManagerException):
    """
    Exception thrown when error occurs during downloading manifest file.
    """
    pass


class ManifestNotFoundException(ManifestDownloadException):
    """
    Exception thrown when manifest file is not found under given address.
    """
    pass


@dataclass
class Manifest:
    """
    Class representing manifest file containing encrypted addresses for validators.
    """

    encrypted_url_mapping: dict[Hotkey, bytes]
    """ Mapping with addresses for validators (validator HotKey -> encrypted url) """
    md5_hash: str
    """ MD5 hash of the manifest data """


class AbstractManifestSerializer(ABC):
    """
    Class used to serialize and deserialize manifest file.
    """

    @abstractmethod
    def serialize(self, manifest: Manifest) -> bytes:
        """
        Serialize manifest. Output format depends on the implementation.
        """
        pass

    @abstractmethod
    def deserialize(self, serialized_data: bytes) -> Manifest:
        """
        Deserialize manifest. Throws ManifestDeserializationException if data format is not recognized.
        """
        pass


class JsonManifestSerializer(AbstractManifestSerializer):
    """
    Manifest serializer implementation which serialize manifest to Json.
    """

    MANIFEST_ROOT_JSON_KEY: str = "ddos_shield_manifest"

    encoding: str

    def __init__(self, encoding: str = "utf-8"):
        """
        Args:
            encoding: Encoding used for transforming Json string to bytes.
        """
        self.encoding = encoding

    def serialize(self, manifest: Manifest) -> bytes:
        data: dict = {
            self.MANIFEST_ROOT_JSON_KEY: asdict(manifest)  # type: ignore
        }
        json_str: str = json.dumps(data, default=self._custom_encoder)
        return json_str.encode(encoding=self.encoding)

    def deserialize(self, serialized_data: bytes) -> Manifest:
        try:
            json_str: str = serialized_data.decode(encoding=self.encoding)
            data = json.loads(json_str, object_hook=self._custom_decoder)
            return Manifest(**data[self.MANIFEST_ROOT_JSON_KEY])
        except Exception as e:
            raise ManifestDeserializationException(f"Failed to deserialize manifest data: {e}") from e

    @staticmethod
    def _custom_encoder(obj: Any) -> Any:
        if isinstance(obj, Hotkey):
            return str(obj)

        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode()  # type: ignore

    @staticmethod
    def _custom_decoder(json_mapping: dict[str, Any]) -> Any:
        if "encrypted_url_mapping" in json_mapping:
            decoded_mapping: dict[Hotkey, bytes] = {}
            for hotkey, encoded_address in json_mapping["encrypted_url_mapping"].items():
                decoded_mapping[Hotkey(hotkey)] = base64.b64decode(encoded_address.encode())
            json_mapping["encrypted_url_mapping"] = decoded_mapping
        return json_mapping


class ReadOnlyManifestManager(ABC):
    """
    Manifest manager only for getting file uploaded by ManifestManager.
    """

    manifest_serializer: AbstractManifestSerializer
    encryption_manager: AbstractEncryptionManager
    event_processor: AbstractMinerShieldEventProcessor
    _download_timeout: int

    def __init__(self, manifest_serializer: AbstractManifestSerializer,
                 encryption_manager: AbstractEncryptionManager,
                 event_processor: AbstractMinerShieldEventProcessor, download_timeout: int = 10):
        self.manifest_serializer = manifest_serializer
        self.encryption_manager = encryption_manager
        self.event_processor = event_processor
        self._download_timeout = download_timeout

    async def get_manifest(self, url: str) -> Manifest:
        """
        Get manifest file from given url and deserialize it.
        Throws ManifestNotFoundException if file is not found.
        Throws ManifestDeserializationException if data format is not recognized.
        """
        raw_data: Optional[bytes] = await self._get_manifest_file(url)
        if raw_data is None:
            raise ManifestDownloadException(f"Manifest file not found at {url}")
        return self.manifest_serializer.deserialize(raw_data)

    async def get_manifests(self, urls: Dict[Hotkey, Optional[str]]) -> Dict[Hotkey, Optional[Manifest]]:
        """
        Get manifest files from given urls and deserialize them. If url is None, None is returned in the result.
        None is also returned if manifest file is not found or has invalid format.

        Args:
            urls: Dictionary with urls for neurons (neuron HotKey -> url).
        """
        raw_manifests_data: Dict[Hotkey, Optional[bytes]] = await self._get_manifest_files(urls)
        manifests: Dict[Hotkey, Optional[Manifest]] = {}
        for hotkey, raw_data in raw_manifests_data.items():
            manifest: Optional[Manifest] = None
            if raw_data is not None:
                try:
                    manifest = self.manifest_serializer.deserialize(raw_data)
                except ManifestDeserializationException:
                    self.event_processor.event('Manifest file corrupted for hotkey={hotkey}, url={url}',
                                               hotkey=hotkey, url=urls[hotkey])
            manifests[hotkey] = manifest
        return manifests

    def get_address_for_validator(self, manifest: Manifest, validator_hotkey: Hotkey,
                                  validator_private_key: PrivateKey) -> str:
        """
        Get URL for validator identified by hotkey from manifest. Decrypts address using validator's private key.
        """
        encrypted_url: bytes = manifest.encrypted_url_mapping[validator_hotkey]
        decrypted_url: bytes = self.encryption_manager.decrypt(validator_private_key, encrypted_url)
        return decrypted_url.decode()

    async def _get_manifest_file(self, url: Optional[str]) -> Optional[bytes]:
        if url is None:
            return None

        async with httpx.AsyncClient() as client:
            try:
                response: httpx.Response = await client.get(url, timeout=self._download_timeout)
                response.raise_for_status()
                return response.content
            except httpx.HTTPStatusError as e:
                if e.response.status_code in (HTTPStatus.FORBIDDEN, HTTPStatus.NOT_FOUND):
                    # REMARK: S3 returns 403 Forbidden if file does not exist in bucket.
                    self.event_processor.event('Manifest file not found, url={url}, status code={status_code}',
                                               url=url, status_code=e.response.status_code)
                    return None
                raise ManifestDownloadException(f'HTTP error when downloading file from {url}: {e}') from e
            except httpx.RequestError as e:
                raise ManifestDownloadException(f'Failed to download file from {url}: {e}') from e

    async def _get_manifest_file_with_retry(self, url: Optional[str]) -> Optional[bytes]:
        try:
            return await self._get_manifest_file(url)
        except ManifestDownloadException:
            return await self._get_manifest_file(url)  # Retry once

    async def _get_manifest_files(self, urls: Dict[Hotkey, Optional[str]]) -> Dict[Hotkey, Optional[bytes]]:
        """
        Get manifest files from given urls. If url is None, None is returned in the result. None is also returned if
        manifest file is not found.

        Args:
            urls: Dictionary with urls for neurons (neuron HotKey -> url).
        """
        tasks = [self._get_manifest_file_with_retry(url) for url in urls.values()]
        results = await asyncio.gather(*tasks)
        return dict(zip(urls.keys(), results))


class AbstractManifestManager(ReadOnlyManifestManager):
    """
    Abstract base class for manager handling manifest file containing encrypted addresses for validators.
    """

    def upload_manifest(self, manifest: Manifest):
        data: bytes = self.manifest_serializer.serialize(manifest)
        return self._put_manifest_file(data)

    def create_manifest(self, address_mapping: MappingProxyType[Hotkey, Address],
                        validators_public_keys: MappingProxyType[Hotkey, PublicKey]) -> Manifest:
        """
        Create manifest with encrypted addresses for validators.

        Args:
            address_mapping: Dictionary containing address mapping (validator HotKey -> Address).
            validators_public_keys: Dictionary containing public keys of validators (validator HotKey -> PublicKey).
        """
        encrypted_address_mapping: dict[Hotkey, bytes] = {}
        md5_hash = hashlib.md5()

        for hotkey, address in address_mapping.items():
            public_key: PublicKey = validators_public_keys[hotkey]
            url: str = f'{address.address}:{address.port}'
            serialized_url: bytes = url.encode()
            encrypted_address_mapping[hotkey] = self.encryption_manager.encrypt(public_key, serialized_url)

            md5_hash.update(hotkey.encode())  # type: ignore
            public_key_bytes: bytes = public_key.encode() if isinstance(public_key, str) else public_key
            md5_hash.update(public_key_bytes)  # type: ignore
            md5_hash.update(serialized_url)  # type: ignore

        return Manifest(encrypted_address_mapping, md5_hash.hexdigest())

    @abstractmethod
    def get_manifest_url(self) -> str:
        """
        Return URL where manifest file is stored.
        """
        pass

    @abstractmethod
    def _put_manifest_file(self, data: bytes):
        """
        Put manifest file into the storage. Should overwrite manifest file if it exists.
        """
        pass


class S3ManifestManager(AbstractManifestManager):
    """
    Manifest manager using AWS S3 service to manage file.
    """

    MANIFEST_FILE_NAME: str = "shield_manifest.json"

    _aws_client_factory: AWSClientFactory
    _bucket_name: str

    def __init__(self, manifest_serializer: AbstractManifestSerializer,
                 encryption_manager: AbstractEncryptionManager, event_processor: AbstractMinerShieldEventProcessor,
                 aws_client_factory: AWSClientFactory, bucket_name: str, download_timeout: int = 10):
        super().__init__(manifest_serializer, encryption_manager, event_processor, download_timeout)
        self._aws_client_factory = aws_client_factory
        self._bucket_name = bucket_name

    def get_manifest_url(self) -> str:
        region_name: str = self._aws_client_factory.aws_region_name
        return f"https://{self._bucket_name}.s3.{region_name}.amazonaws.com/{self.MANIFEST_FILE_NAME}"

    @functools.cached_property
    def _s3_client(self) -> BaseClient:
        return self._aws_client_factory.boto3_client("s3")

    def _put_manifest_file(self, data: bytes):
        self._s3_client.put_object(Bucket=self._bucket_name, Key=self.MANIFEST_FILE_NAME, Body=data, ACL='public-read')
