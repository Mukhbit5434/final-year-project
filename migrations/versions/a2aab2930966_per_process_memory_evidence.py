"""per-process memory evidence

Revision ID: a2aab2930966
Revises: fda781d38f87
Create Date: 2026-08-02 15:27:16.998569

"""
from alembic import op
import sqlalchemy as sa


revision = 'a2aab2930966'
down_revision = 'fda781d38f87'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('jobs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('evidence', sa.JSON(), nullable=True))



def downgrade():
    with op.batch_alter_table('jobs', schema=None) as batch_op:
        batch_op.drop_column('evidence')

