"""mac headsup

Revision ID: 02b6b24200af
Revises: 80419263930a
Create Date: 2016-02-11 19:26:27.899610

"""

# revision identifiers, used by Alembic.
revision = '02b6b24200af'
down_revision = '3f0c11478a5d'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'quark_worker_sync',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB'
    )
    op.create_table(
        'quark_available_mac_addresses',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('address', sa.BigInteger(), nullable=False),
        sa.Column('mac_range', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['address'],
                                ['quark_mac_addresses.address'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['mac_range'],
                                ['quark_mac_address_ranges.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        mysql_engine='InnoDB'
    )


def downgrade():
    op.drop_table('quark_worker_sync')
