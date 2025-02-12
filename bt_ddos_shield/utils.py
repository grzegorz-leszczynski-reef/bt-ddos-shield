import functools
from dataclasses import dataclass

import bittensor
import bittensor_wallet
import boto3
import route53
from botocore.client import BaseClient
from pydantic import BaseModel
from route53.connection import Route53Connection

type Hotkey = str
type PublicKey = str
type PrivateKey = str


@dataclass
class Address:
    """
    Class describing address created by DDosShield.
    """

    address_id: str
    """ Identifier of the address """
    address: str
    """ Domain address used to connecting to Miner's server """
    port: int
    """ Port used to connecting to Miner's server """

    def __repr__(self):
        return f"Address(id={self.address_id}, address={self.address}:{self.port})"


class AWSClientFactory:
    aws_access_key_id: str
    aws_secret_access_key: str
    aws_region_name: str | None

    def __init__(self, aws_access_key_id: str, aws_secret_access_key: str, aws_region_name: str | None = None):
        """
        Args:
            aws_access_key_id: AWS access key ID.
            aws_secret_access_key: AWS secret access key.
            aws_region_name: AWS region name. If not known, it can be set later using set_aws_region_name method.
        """
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.aws_region_name = aws_region_name

    def set_aws_region_name(self, aws_region_name: str) -> bool:
        """Set AWS region name. Returns if region name was changed."""
        if self.aws_region_name == aws_region_name:
            return False
        self.aws_region_name = aws_region_name
        return True

    def boto3_client(self, service_name: str) -> BaseClient:
        return boto3.client(
            service_name,
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
            region_name=self.aws_region_name,
        )

    def route53_client(self) -> Route53Connection:
        return route53.connect(self.aws_access_key_id, self.aws_secret_access_key)


class WalletSettings(BaseModel):
    name: str | None = None
    hotkey: str | None = None
    path: str | None = None

    @functools.cached_property
    def instance(self) -> bittensor_wallet.Wallet:
        return bittensor.Wallet(**self.model_dump())


class SubtensorSettings(BaseModel):
    network: str | None = None

    @functools.cached_property
    def client(self) -> bittensor.Subtensor:
        return self.create_client()

    def create_client(self) -> bittensor.Subtensor:
        return bittensor.Subtensor(**self.model_dump())
