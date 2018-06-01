# Copyright 2016 <PUT YOUR NAME/COMPANY HERE>
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

"""Add vni to bgpvpn table

Revision ID: 16a90a86623f
Revises: 0ab4049986b8
Create Date: 2016-06-22 03:33:55.812982

"""

# revision identifiers, used by Alembic.
revision = '16a90a86623f'
down_revision = '0ab4049986b8'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('bgpvpns', sa.Column('vni', sa.Integer))
