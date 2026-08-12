"""artifact type nullable pending analyst confirmation

Revision ID: eb17c935e9af
Revises: 01e40b72559d
Create Date: 2026-07-29 00:12:28.688455

"""
from alembic import op
import sqlalchemy as sa


revision = 'eb17c935e9af'
down_revision = '01e40b72559d'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('jobs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('detected_as', sa.String(length=32), nullable=True))
        batch_op.alter_column('artifact',
               existing_type=sa.VARCHAR(length=8),
               nullable=True)



def downgrade():
    with op.batch_alter_table('jobs', schema=None) as batch_op:
        batch_op.alter_column('artifact',
               existing_type=sa.VARCHAR(length=8),
               nullable=False)
        batch_op.drop_column('detected_as')

