"""users, jobs, results, findings, audit_log

Revision ID: 01e40b72559d
Revises: 
Create Date: 2026-07-28 23:49:29.548840

"""
from alembic import op
import sqlalchemy as sa


revision = '01e40b72559d'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=64), nullable=False),
    sa.Column('email', sa.String(length=255), nullable=True),
    sa.Column('pw_hash', sa.String(length=255), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_users_username'), ['username'], unique=True)

    op.create_table('jobs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('filename', sa.String(length=512), nullable=False),
    sa.Column('stored_name', sa.String(length=128), nullable=False),
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.Column('size_bytes', sa.BigInteger(), nullable=False),
    sa.Column('artifact', sa.String(length=8), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('started_at', sa.DateTime(), nullable=True),
    sa.Column('finished_at', sa.DateTime(), nullable=True),
    sa.Column('files_scanned', sa.Integer(), nullable=True),
    sa.Column('files_flagged', sa.Integer(), nullable=True),
    sa.Column('skipped', sa.JSON(), nullable=True),
    sa.Column('extraction_gaps', sa.JSON(), nullable=True),
    sa.Column('ood_count', sa.Integer(), nullable=True),
    sa.Column('ood_fields', sa.JSON(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('stored_name')
    )
    with op.batch_alter_table('jobs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_jobs_sha256'), ['sha256'], unique=False)
        batch_op.create_index(batch_op.f('ix_jobs_status'), ['status'], unique=False)
        batch_op.create_index(batch_op.f('ix_jobs_user_id'), ['user_id'], unique=False)

    op.create_table('audit_log',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('job_id', sa.Integer(), nullable=True),
    sa.Column('action', sa.String(length=32), nullable=False),
    sa.Column('detail', sa.Text(), nullable=True),
    sa.Column('ip', sa.String(length=45), nullable=True),
    sa.Column('at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['job_id'], ['jobs.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('audit_log', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_audit_log_at'), ['at'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_log_job_id'), ['job_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_log_user_id'), ['user_id'], unique=False)

    op.create_table('results',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('job_id', sa.Integer(), nullable=False),
    sa.Column('probability', sa.Float(), nullable=False),
    sa.Column('threshold', sa.Float(), nullable=False),
    sa.Column('malicious', sa.Boolean(), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=True),
    sa.Column('severity_note', sa.String(length=255), nullable=True),
    sa.Column('path', sa.Text(), nullable=True),
    sa.Column('partition', sa.String(length=64), nullable=True),
    sa.Column('inode', sa.String(length=64), nullable=True),
    sa.Column('file_sha256', sa.String(length=64), nullable=True),
    sa.Column('file_md5', sa.String(length=32), nullable=True),
    sa.Column('file_size', sa.BigInteger(), nullable=True),
    sa.Column('allocated', sa.Boolean(), nullable=True),
    sa.Column('data_offset', sa.BigInteger(), nullable=True),
    sa.Column('mtime', sa.DateTime(), nullable=True),
    sa.Column('atime', sa.DateTime(), nullable=True),
    sa.Column('ctime', sa.DateTime(), nullable=True),
    sa.Column('btime', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['job_id'], ['jobs.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('results', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_results_file_sha256'), ['file_sha256'], unique=False)
        batch_op.create_index(batch_op.f('ix_results_job_id'), ['job_id'], unique=False)

    op.create_table('findings',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('result_id', sa.Integer(), nullable=False),
    sa.Column('feature', sa.String(length=128), nullable=False),
    sa.Column('weight', sa.Float(), nullable=True),
    sa.Column('rank', sa.Integer(), nullable=True),
    sa.Column('meaning', sa.Text(), nullable=True),
    sa.Column('tag', sa.String(length=64), nullable=True),
    sa.Column('mitre_id', sa.String(length=16), nullable=True),
    sa.Column('mitre_name', sa.String(length=128), nullable=True),
    sa.Column('confidence', sa.String(length=16), nullable=True),
    sa.ForeignKeyConstraint(['result_id'], ['results.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_findings_result_id'), ['result_id'], unique=False)



def downgrade():
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_findings_result_id'))

    op.drop_table('findings')
    with op.batch_alter_table('results', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_results_job_id'))
        batch_op.drop_index(batch_op.f('ix_results_file_sha256'))

    op.drop_table('results')
    with op.batch_alter_table('audit_log', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_audit_log_user_id'))
        batch_op.drop_index(batch_op.f('ix_audit_log_job_id'))
        batch_op.drop_index(batch_op.f('ix_audit_log_at'))

    op.drop_table('audit_log')
    with op.batch_alter_table('jobs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_jobs_user_id'))
        batch_op.drop_index(batch_op.f('ix_jobs_status'))
        batch_op.drop_index(batch_op.f('ix_jobs_sha256'))

    op.drop_table('jobs')
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_users_username'))

    op.drop_table('users')
