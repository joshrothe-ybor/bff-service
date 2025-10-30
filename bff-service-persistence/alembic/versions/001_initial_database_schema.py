"""Initial database schema

Revision ID: 001
Revises: 
Create Date: 2025-01-01 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create initial database schema."""
    # Create bff table
    op.create_table(
        'bff',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False, comment="Name of the bff"),
        sa.Column('description', sa.Text(), nullable=True, comment="Description of the bff"),
        sa.Column('status', sa.String(50), nullable=False, default='ACTIVE', 
                 comment="Status of the bff (ACTIVE, INACTIVE, ARCHIVED)"),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                 comment="Timestamp when the entity was created"),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True,
                 comment="Timestamp when the entity was last updated"),
        sa.Column('version', sa.Integer(), nullable=False, default=1,
                 comment="Version number for optimistic locking"),
    )
    
    # Create indexes for performance
    op.create_index('ix_bff_name', 'bff', ['name'])
    op.create_index('ix_bff_status', 'bff', ['status'])
    op.create_index('ix_bff_created_at', 'bff', ['created_at'])
    op.create_index('ix_bff_updated_at', 'bff', ['updated_at'])
    
    # Create unique constraint on name
    op.create_unique_constraint('uq_bff_name', 'bff', ['name'])


def downgrade() -> None:
    """Drop initial database schema."""
    op.drop_table('bff') 