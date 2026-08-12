"""case reference

Revision ID: 169e193a148b
Revises: 249a2a3baaa5
Create Date: 2026-08-10 09:56:03.967680

"""
from alembic import op
import sqlalchemy as sa


revision = '169e193a148b'
down_revision = '249a2a3baaa5'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('jobs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('case_reference', sa.String(length=128), nullable=True))



def downgrade():
    with op.batch_alter_table('jobs', schema=None) as batch_op:
        batch_op.drop_column('case_reference')

