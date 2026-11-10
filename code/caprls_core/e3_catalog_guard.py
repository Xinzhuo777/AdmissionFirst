"""Finite catalog predicate, for already validated claims only.

This renderer issues no authorization. It decomposes the former fixed JSON
equality into catalog predicates, retaining its complete finite premises.
"""
from __future__ import annotations

import json
from typing import Any, Mapping


def _literal(value: Any) -> str:
    if type(value) is bool:
        return 'TRUE' if value else 'FALSE'
    if type(value) is int:
        return str(value)
    if type(value) is str and '\x00' not in value:
        return "E'" + value.replace('\\', '\\\\').replace("'", "''") + "'"
    raise ValueError('unsupported finite catalog literal')


def _membership(expected: list[str], *, member_column: str, joined_column: str) -> str:
    source = f'''FROM pg_catalog.pg_auth_members m
        JOIN pg_catalog.pg_roles p ON p.oid=m.{joined_column}
        WHERE m.{member_column}=r.oid'''
    if not expected:
        # Same joined row set as the former aggregate; no dangling-row or
        # foreign-key assumption is introduced by this empty-list case.
        return '(NOT EXISTS (SELECT 1 '+source+'))'
    return "((SELECT COALESCE(jsonb_agg(p.rolname ORDER BY p.rolname), '[]'::jsonb) " + source + ") IS NOT DISTINCT FROM " + _literal(json.dumps(expected)) + '::jsonb)'


def _exact_text(left: str, operator: str, right: str) -> str:
    # The previous JSONB equality compares string bytes. State that equality
    # explicitly rather than inheriting a catalog/expression collation.
    return f'({left})::text COLLATE pg_catalog."C" {operator} ({right})::text COLLATE pg_catalog."C"'


def render_validated_catalog_guard(claims: Mapping[str, Any]) -> str:
    """Render the accepted finite domain; caller must validate profile origin.

    Unique public relation names and OIDs, builtin-only columns, and the exact
    validator configuration are checked here too because they justify the
    decomposition. A profile outside this domain is rejected, never weakened.
    """
    if type(claims) is not dict or set(claims) != {'database','role','relations','artifact_validator'}:
        raise ValueError('catalog claim shape changed')
    if type(claims['database']) is not str or not claims['database']:
        raise ValueError('database claim is not a name')
    role, relations, validator = claims['role'], claims['relations'], claims['artifact_validator']
    if type(role) is not dict or set(role) != {'role_name','is_superuser','bypasses_rls','member_of','members'}:
        raise ValueError('role claim shape changed')
    if type(role['role_name']) is not str or not role['role_name']:
        raise ValueError('role claim is not a name')
    if any(type(role[k]) is not bool for k in ('is_superuser','bypasses_rls')):
        raise ValueError('role claim flags are not booleans')
    if any(type(role[k]) is not list or any(type(v) is not str for v in role[k])
           for k in ('member_of','members')):
        raise ValueError('role memberships are not names')
    columns = ('oid','schema_name','relation_name','owner','row_security_enabled',
               'force_row_security','relation_kind','has_rules','has_triggers',
               'has_subclasses','is_partition','builtin_columns_only')
    if type(relations) is not list or not relations:
        raise ValueError('finite relation inventory is empty')
    for relation in relations:
        if type(relation) is not dict or set(relation) != set(columns):
            raise ValueError('finite relation claim shape changed')
        if type(relation['oid']) is not int or not 0 < relation['oid'] < 2**32:
            raise ValueError('finite relation OID is invalid')
        if any(type(relation[k]) is not str for k in ('schema_name','relation_name','owner','relation_kind')):
            raise ValueError('finite relation names are not exact strings')
        if any(type(relation[k]) is not bool for k in columns[4:] if k!='relation_kind'):
            raise ValueError('finite relation flags are not exact booleans')
        if relation['schema_name']!='public' or relation['builtin_columns_only'] is not True:
            raise ValueError('relation is outside accepted finite domain')
    names = [r['relation_name'] for r in relations]
    oids = [r['oid'] for r in relations]
    if names != sorted(set(names)) or len(oids)!=len(set(oids)):
        raise ValueError('finite relation inventory is not canonical')
    if (type(validator) is not dict or set(validator) != {'language','security_definer','config','returns_boolean','body'}
        or validator['language']!='plpgsql' or validator['security_definer'] is not False
        or validator['config'] is not None or validator['returns_boolean'] is not True
        or type(validator['body']) is not str):
        raise ValueError('validator is outside accepted finite domain')
    rows = ',\n      '.join('('+', '.join(_literal(r[k])+('::oid' if k=='oid' else '') for k in columns)+')'
                         for r in relations)
    actual_columns = {
        'schema_name':'n.nspname', 'relation_name':'c.relname', 'owner':'c.relowner::regrole::text',
        'row_security_enabled':'c.relrowsecurity', 'force_row_security':'c.relforcerowsecurity',
        'relation_kind':'c.relkind::text', 'has_rules':'c.relhasrules', 'has_triggers':'c.relhastriggers',
        'has_subclasses':'c.relhassubclass', 'is_partition':'c.relispartition',
    }
    string_columns = {'schema_name','relation_name','owner','relation_kind'}
    differences = ' OR\n        '.join(
        _exact_text(actual, 'IS DISTINCT FROM', 'e.'+key) if key in string_columns
        else actual+' IS DISTINCT FROM e.'+key for key,actual in actual_columns.items())
    oid_list = ', '.join(str(oid)+'::oid' for oid in oids)
    membership = _membership(role['member_of'],member_column='member',joined_column='roleid')
    members = _membership(role['members'],member_column='roleid',joined_column='member')
    return f'''(
  {_exact_text('current_database()', 'IS NOT DISTINCT FROM', _literal(claims['database']))}
  AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
    WHERE r.rolname=session_user AND {_exact_text('r.rolname', 'IS NOT DISTINCT FROM', _literal(role['role_name']))}
      AND r.rolsuper IS NOT DISTINCT FROM {_literal(role['is_superuser'])}
      AND r.rolbypassrls IS NOT DISTINCT FROM {_literal(role['bypasses_rls'])}
      AND {membership} AND {members})
  AND NOT EXISTS (
    SELECT 1 FROM (VALUES {rows}) AS e({', '.join(columns)})
    LEFT JOIN pg_catalog.pg_class c ON c.oid=e.oid
    LEFT JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE c.oid IS NULL OR {differences})
  AND NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_attribute a
    JOIN pg_catalog.pg_type t ON t.oid=a.atttypid
    JOIN pg_catalog.pg_namespace tn ON tn.oid=t.typnamespace
    LEFT JOIN pg_catalog.pg_collation co ON co.oid=a.attcollation
    LEFT JOIN pg_catalog.pg_namespace cn ON cn.oid=co.collnamespace
    WHERE a.attrelid IN ({oid_list}) AND a.attnum>0 AND NOT a.attisdropped
      AND (tn.nspname<>'pg_catalog' OR t.typtype<>'b' OR a.attgenerated<>''
        OR (a.attcollation<>0 AND cn.nspname<>'pg_catalog')))
  AND EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
    WHERE p.oid=pg_catalog.to_regprocedure('public.caprls_assert_artifact_valid(text,jsonb)')
      AND {_exact_text('l.lanname', 'IS NOT DISTINCT FROM', _literal(validator['language']))}
      AND p.prosecdef IS NOT DISTINCT FROM FALSE AND p.proconfig IS NULL
      AND p.prorettype='boolean'::regtype
      AND {_exact_text('p.prosrc', 'IS NOT DISTINCT FROM', _literal(validator['body']))})
)'''
