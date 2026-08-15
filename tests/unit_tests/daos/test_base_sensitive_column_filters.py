# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""Tests that credential columns cannot be used as DAO filter columns.

``LIKE``-style operators on a credential column turn the row count into a
prefix oracle for a value that is never serialized in any response, so the DAO
layer rejects them regardless of what a caller passes down.
"""

from typing import Any

import pytest
from sqlalchemy.orm import Session

from superset.daos.base import BaseDAO, ColumnOperator, ColumnOperatorEnum
from superset.daos.database import DatabaseDAO
from superset.daos.user import UserDAO


def _probe(dao: type[BaseDAO[Any]], session: Session, col: str, prefix: str) -> int:
    query = dao.apply_column_operators(
        session.query(dao.model_cls),
        [ColumnOperator(col=col, opr=ColumnOperatorEnum.sw, value=prefix)],
    )
    return query.count()


def test_database_credential_columns_are_not_filterable(session: Session) -> None:
    from superset.models.core import Database

    Database.metadata.create_all(session.get_bind())
    database = Database(database_name="prod")
    database.set_sqlalchemy_uri("postgresql://analytics:s3cret@10.0.0.7:5432/warehouse")
    session.add(database)
    session.flush()

    for column in ("password", "sqlalchemy_uri", "encrypted_extra", "server_cert"):
        with pytest.raises(ValueError, match="cannot be used as a filter"):
            _probe(DatabaseDAO, session, column, "postgresql")

    # Non-sensitive columns keep working.
    assert _probe(DatabaseDAO, session, "database_name", "pro") == 1


def test_database_credential_columns_are_not_advertised() -> None:
    filterable = DatabaseDAO.get_filterable_columns_and_operators()
    assert "password" not in filterable
    assert "sqlalchemy_uri" not in filterable
    assert "encrypted_extra" not in filterable
    assert "server_cert" not in filterable
    assert "database_name" in filterable


def test_user_password_hash_is_not_filterable(session: Session) -> None:
    from flask_appbuilder.security.sqla.models import User

    User.metadata.create_all(session.get_bind())
    session.add(
        User(
            first_name="Alice",
            last_name="Doe",
            username="alice",
            email="alice@example.com",
            password="pbkdf2:sha256:some-hash",  # noqa: S106
        )
    )
    session.flush()

    with pytest.raises(ValueError, match="cannot be used as a filter"):
        _probe(UserDAO, session, "password", "pbkdf2")

    assert _probe(UserDAO, session, "username", "ali") == 1
    assert "password" not in UserDAO.get_filterable_columns_and_operators()
