# Copyright 2017 Wind River Systems, Ltd.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
#
# Copyright (c) 2017 Wind River Systems, Inc.
#

"""add evpn related tables

Revision ID: f808e07da389
Revises: 16a90a86623f
Create Date: 2017-08-29 18:11:46.470054

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'f808e07da389'
down_revision = '16a90a86623f'


def upgrade():
    op.create_table(
        'wrs_bgpvpn_learned_gateways',
        sa.Column('id', sa.String(36),
                  nullable=False, primary_key=True),
        sa.Column('agent_id', sa.String(36),
                  sa.ForeignKey("agents.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column('bgpvpn_id', sa.String(36),
                  sa.ForeignKey("bgpvpns.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column('ip_address', sa.String(64), nullable=False),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=True),
        sa.UniqueConstraint('agent_id', 'bgpvpn_id', 'ip_address',
                            name='unique_gateway0agent0vpn0ip'),
        sa.Index('unique_gateway_index', 'agent_id', 'bgpvpn_id',
                 'ip_address'))

    op.create_table(
        'wrs_bgpvpn_learned_devices',
        sa.Column('id', sa.String(36), nullable=False, primary_key=True),
        sa.Column('agent_id', sa.String(36), nullable=False),
        sa.Column('bgpvpn_id', sa.String(36), nullable=False),
        sa.Column('mac_address', sa.String(20), nullable=False),
        sa.Column('ip_address', sa.String(64), nullable=False),
        sa.Column('gateway_ip', sa.String(64), nullable=False),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=True),
        sa.ForeignKeyConstraint(['agent_id', 'bgpvpn_id', 'gateway_ip'],
                                ['wrs_bgpvpn_learned_gateways.agent_id',
                                 'wrs_bgpvpn_learned_gateways.bgpvpn_id',
                                 'wrs_bgpvpn_learned_gateways.ip_address'],
                                name='gateway_fkey0agent@vpn@vtep',
                                ondelete="CASCADE"),
        sa.UniqueConstraint('agent_id', 'bgpvpn_id', 'mac_address',
                            'ip_address',
                            name='unique_device0agent0vpn0mac0ip'),
        sa.Index('unique_device_index',
                 'agent_id', 'bgpvpn_id', 'mac_address', 'ip_address'))
