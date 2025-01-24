"""Add channel_name to Message

Revision ID: 7cb97076e175
Revises: 9398b5a3eb9b
Create Date: 2025-01-19 20:01:01.789701

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7cb97076e175'
down_revision = '9398b5a3eb9b'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('message', schema=None) as batch_op:
        batch_op.add_column(sa.Column('channel_name', sa.String(length=80), nullable=False, server_default='general'))


    # ### end Alembic commands ###


def downgrade():
    with op.batch_alter_table('message', schema=None) as batch_op:
        batch_op.drop_column('channel_name')


    # ### end Alembic commands ###
