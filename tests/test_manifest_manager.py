from typing import Optional

import pytest
from bt_ddos_shield.encryption_manager import ECIESEncryptionManager
from bt_ddos_shield.manifest_manager import (
    AbstractManifestManager,
    JsonManifestSerializer,
    Manifest,
    ManifestNotFoundException,
    ReadOnlyManifestManager,
    S3ManifestManager,
)
from bt_ddos_shield.utils import AWSClientFactory, Hotkey
from tests.conftest import ShieldTestSettings


class MemoryManifestManager(AbstractManifestManager):
    _manifest_url: str
    stored_file: Optional[bytes]
    put_counter: int

    def __init__(self):
        super().__init__(JsonManifestSerializer(), ECIESEncryptionManager())
        self._manifest_url = 'https://manifest.com'
        self.stored_file = None
        self.put_counter = 0

    def get_manifest_url(self) -> str:
        return self._manifest_url

    def _put_manifest_file(self, data: bytes):
        self.stored_file = data
        self.put_counter += 1

    def _get_manifest_file(self, url: str) -> bytes:
        if self.stored_file is None or url != self._manifest_url:
            raise ManifestNotFoundException(f"Manifest file not found under url: {url}")
        return self.stored_file


class TestManifestManager:
    """
    Test suite for the manifest manager.
    """

    def test_json_serializer(self):
        manifest_serializer = JsonManifestSerializer()
        mapping: dict[Hotkey, bytes] = {Hotkey('validator1'): b'address1', Hotkey('validator2'): b'address2'}
        md5_hash: str = "some_hash"
        manifest: Manifest = Manifest(mapping, md5_hash)
        json_data: bytes = manifest_serializer.serialize(manifest)
        deserialized_manifest: Manifest = manifest_serializer.deserialize(json_data)
        assert manifest == deserialized_manifest

    def test_s3_put_get(self, shield_settings: ShieldTestSettings):
        """ Test S3ManifestManager class. Put manifest file, get it and check if it was stored correctly. """
        aws_client_factory: AWSClientFactory = AWSClientFactory(shield_settings.aws_access_key_id,
                                                                shield_settings.aws_secret_access_key,
                                                                shield_settings.aws_region_name)
        manifest_manager = S3ManifestManager(aws_client_factory=aws_client_factory,
                                             bucket_name=shield_settings.aws_s3_bucket_name,
                                             manifest_serializer=JsonManifestSerializer(),
                                             encryption_manager=ECIESEncryptionManager())

        data: bytes = b'some_data'
        manifest_manager._put_manifest_file(data)
        manifest_url: str = manifest_manager.get_manifest_url()
        retrieved_data: bytes = manifest_manager._get_manifest_file(manifest_url)
        assert retrieved_data == data

        with pytest.raises(ManifestNotFoundException):
            manifest_manager._get_manifest_file(manifest_url + 'xxx')

        other_data: bytes = b'other_data'
        manifest_manager._put_manifest_file(other_data)
        retrieved_data: bytes = manifest_manager._get_manifest_file(manifest_url)
        assert retrieved_data == other_data

        validator_manifest_manager = ReadOnlyManifestManager(manifest_serializer=JsonManifestSerializer(),
                                                             encryption_manager=ECIESEncryptionManager())
        retrieved_data: bytes = validator_manifest_manager._get_manifest_file(manifest_url)
        assert retrieved_data == other_data
