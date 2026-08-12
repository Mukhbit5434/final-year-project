"""volumetric context

Revision ID: 249a2a3baaa5
Revises: a2aab2930966
Create Date: 2026-08-02 16:40:03.038493

"""
from alembic import op
import sqlalchemy as sa


revision = '249a2a3baaa5'
down_revision = 'a2aab2930966'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('jobs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('volumetric', sa.JSON(), nullable=True))



def downgrade():
    with op.batch_alter_table('jobs', schema=None) as batch_op:
        batch_op.drop_column('volumetric')

