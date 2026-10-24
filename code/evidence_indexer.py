import sys
sys.stdout.reconfigure(encoding='utf-8')
import os, json, glob, re, hashlib
import pandas as pd
from collections import defaultdict

class EvidenceIndexer:
    def __init__(self, dataset_dir='dataset'):
        self.dataset_dir = dataset_dir
        self.ev_manifest = pd.read_csv(os.path.join(dataset_dir, 'evidence_files.csv'))
        self.ev_map = {}
        for idx, r in self.ev_manifest.iterrows():
            self.ev_map[r['file_id']] = {
                'file_id': r['file_id'],
                'file_path': os.path.join(dataset_dir, r['file_path']).replace('\\', '/'),
                'origin': r['origin'],
                'captured_at': r['captured_at']
            }
        self.observations = [] # list of dicts

    def add_obs(self, file_id, captured_at, system_id, resource_id, category, raw_state, identifier=None, details=None):
        if not resource_id or not system_id:
            return
        self.observations.append({
            'file_id': file_id,
            'captured_at': captured_at,
            'system_id': system_id,
            'resource_id': resource_id,
            'category': category,
            'raw_state': raw_state,
            'identifier': str(identifier).lower() if identifier else None,
            'details': details or {}
        })

    def parse_all(self):
        for fid, info in self.ev_map.items():
            fpath = info['file_path']
            origin = info['origin']
            cat_at = info['captured_at']
            if not os.path.exists(fpath):
                continue
            
            # 1. Handover text
            if fpath.endswith('.txt'):
                self._parse_txt(fid, fpath, cat_at)
            # 2. JSON files
            elif fpath.endswith('.json'):
                self._parse_json(fid, fpath, cat_at, origin)
            # 3. SQL files
            elif fpath.endswith('.sql'):
                self._parse_sql(fid, fpath, cat_at, origin)
            # 4. LOG files
            elif fpath.endswith('.log'):
                self._parse_log(fid, fpath, cat_at, origin)
            # 5. Documents / Images
            elif fpath.endswith(('.pdf', '.png')):
                self._parse_binaries(fid, fpath, cat_at, origin)

        print(f"Total observations indexed: {len(self.observations)}")
        return self.observations

    def _parse_txt(self, fid, fpath, cat_at):
        with open(fpath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith('-'):
                    parts = [p.strip() for p in line[1:].split('|')]
                    if len(parts) >= 6:
                        ts, sys_id, res_id, cat, st, ident = parts[:6]
                        raw_st = 'ABSENT' if st == 'NOT_FOUND' else ('ACTIVE' if st == 'ACTIVE' else ('DISABLED' if st == 'DISABLED' else ('BLOCKED' if st == 'BLOCKED' else ('REDACTED' if st == 'REDACTED' else ('ANONYMIZED' if st == 'ANONYMIZED' else 'PRESENT')))))
                        self.add_obs(fid, cat_at, sys_id, res_id, cat, raw_st, ident)

    def _parse_json(self, fid, fpath, cat_at, origin):
        with open(fpath, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
            except:
                return

        # service_resource_export
        if origin == 'service_resource_export' or 'service_exports' in data:
            file_exp_at = data.get('exported_at') or cat_at
            exports = data.get('service_exports', {})
            for sys_id, content in exports.items():
                if sys_id == 'account_service':
                    for item in content.get('profile_lookups', []):
                        prof = item.get('profile')
                        status = item.get('status_code')
                        res_id = item.get('resource_id')
                        st = 'ABSENT' if (status == 404 or prof is None) else 'PRESENT'
                        ident = prof.get('email') or prof.get('customer_reference') if prof else None
                        self.add_obs(fid, file_exp_at, sys_id, res_id, 'USER_PROFILE', st, ident)
                elif sys_id == 'analytics_platform':
                    for item in content.get('profiles', []):
                        res_id = item.get('resource_id')
                        ident = item.get('email') or item.get('customer_reference')
                        has_pii = bool(item.get('email') or item.get('customer_reference') or item.get('phone') or item.get('email_hash'))
                        st = 'PRESENT' if has_pii else 'ANONYMIZED'
                        self.add_obs(fid, file_exp_at, sys_id, res_id, 'ANALYTICS_PROFILE', st, ident)
                elif sys_id == 'backup_service':
                    for item in content.get('restore_entries', []):
                        res_id = item.get('resource_id')
                        ident = item.get('customer_email') or item.get('customer_reference')
                        st = 'ACTIVE' if item.get('restore_allowed') else 'BLOCKED'
                        self.add_obs(fid, file_exp_at, sys_id, res_id, 'BACKUP_ARCHIVE', st, ident)
                elif sys_id == 'export_service':
                    for item in content.get('exports', []):
                        res_id = item.get('resource_id')
                        ident = item.get('owner_email') or item.get('customer_reference')
                        self.add_obs(fid, file_exp_at, sys_id, res_id, 'USER_EXPORT', 'PRESENT', ident)
                elif sys_id == 'integration_service':
                    for item in content.get('connectors', []):
                        res_id = item.get('resource_id')
                        ident = item.get('customer_email') or item.get('customer_reference')
                        st = 'ACTIVE' if item.get('enabled') else 'DISABLED'
                        self.add_obs(fid, file_exp_at, sys_id, res_id, 'DATA_FLOW', st, ident)
                elif sys_id == 'search_service':
                    for item in content.get('index_queries', []):
                        res_id = item.get('resource_id')
                        ident = item.get('query')
                        hits = item.get('hits', {})
                        st = 'PRESENT' if hits.get('total', 0) > 0 else 'ABSENT'
                        self.add_obs(fid, file_exp_at, sys_id, res_id, 'SEARCH_INDEX_ENTRY', st, ident)
                elif sys_id == 'security_service':
                    for item in content.get('audit_records', []):
                        res_id = item.get('resource_id')
                        ident = item.get('subject_reference')
                        self.add_obs(fid, file_exp_at, sys_id, res_id, 'SECURITY_AUDIT_LOG', 'PRESENT', ident)
                elif sys_id == 'support_platform':
                    for item in content.get('tickets', []):
                        res_id = item.get('resource_id')
                        ident = item.get('requester_email') or item.get('customer_reference')
                        has_pii = bool(item.get('requester_email') or item.get('requester_name') or item.get('requester_phone'))
                        st = 'PRESENT' if has_pii else 'REDACTED'
                        self.add_obs(fid, file_exp_at, sys_id, res_id, 'SUPPORT_MESSAGE', st, ident)

        # records_assurance_snapshot_bundle
        elif origin == 'records_assurance_snapshot_bundle' or 'snapshots' in data:
            snapshots = data.get('snapshots', [])
            for s in snapshots:
                col = s.get('collection')
                snap_cat_at = s.get('captured_at') or cat_at
                for item in s.get('records', []):
                    res_id = item.get('resource_id')
                    if col == 'customer_profiles':
                        ident = item.get('email') or item.get('customer_reference') or item.get('user_id')
                        st = 'ABSENT' if (item.get('account_status') == 'DELETED' and not item.get('email')) else 'PRESENT'
                        self.add_obs(fid, snap_cat_at, 'account_service', res_id, 'USER_PROFILE', st, ident)
                    elif col == 'customer_search_documents':
                        ident = item.get('email') or item.get('customer_reference')
                        self.add_obs(fid, snap_cat_at, 'search_service', res_id, 'SEARCH_INDEX_ENTRY', 'PRESENT', ident)
                    elif col == 'customer_analytics_reports':
                        ident = item.get('email') or item.get('user_id')
                        has_pii = bool(item.get('email') or item.get('user_id') or item.get('phone') or item.get('email_hash'))
                        st = 'PRESENT' if has_pii else 'ANONYMIZED'
                        self.add_obs(fid, snap_cat_at, 'analytics_platform', res_id, 'ANALYTICS_PROFILE', st, ident)
                    elif col == 'backup_catalog':
                        ident = item.get('customer_email') or item.get('customer_reference')
                        st = 'ACTIVE' if item.get('restore_allowed') else 'BLOCKED'
                        self.add_obs(fid, snap_cat_at, 'backup_service', res_id, 'BACKUP_ARCHIVE', st, ident)
                    elif col == 'customer_export_jobs':
                        ident = item.get('owner_email') or item.get('customer_reference')
                        self.add_obs(fid, snap_cat_at, 'export_service', res_id, 'USER_EXPORT', 'PRESENT', ident)
                    elif col == 'connector_configurations':
                        ident = item.get('customer_email') or item.get('customer_reference')
                        st = 'ACTIVE' if item.get('enabled') else 'DISABLED'
                        self.add_obs(fid, snap_cat_at, 'integration_service', res_id, 'DATA_FLOW', st, ident)
                    elif col == 'security_audit_events':
                        ident = item.get('subject_reference')
                        self.add_obs(fid, snap_cat_at, 'security_service', res_id, 'SECURITY_AUDIT_LOG', 'PRESENT', ident)
                    elif col == 'support_conversations':
                        ident = item.get('requester_email') or item.get('customer_reference')
                        has_pii = bool(item.get('requester_email') or item.get('requester_name') or item.get('requester_phone'))
                        st = 'PRESENT' if has_pii else 'REDACTED'
                        self.add_obs(fid, snap_cat_at, 'support_platform', res_id, 'SUPPORT_MESSAGE', st, ident)
                    elif col == 'ticket_attachments':
                        ident = item.get('uploader_email') or item.get('customer_reference')
                        self.add_obs(fid, snap_cat_at, 'support_platform', res_id, 'SUPPORT_ATTACHMENT', 'PRESENT', ident)
                    elif col == 'deleted_customer_references':
                        ident = item.get('subject_reference') or item.get('email')
                        has_pii = bool(item.get('name') or item.get('email') or item.get('phone') or item.get('email_hash'))
                        st = 'PRESENT' if has_pii else 'REDACTED'
                        self.add_obs(fid, snap_cat_at, 'identity_service', res_id, 'ACCOUNT_TOMBSTONE', st, ident)

        # Other specific JSON files
        elif 'records' in data:
            records = data.get('records', [])
            col = data.get('collection', '')
            for item in records:
                res_id = item.get('resource_id')
                if col == 'customer_export_jobs' or origin == 'export_service' or 'export' in fpath:
                    ident = item.get('owner_email') or item.get('customer_reference')
                    self.add_obs(fid, cat_at, 'export_service', res_id, 'USER_EXPORT', 'PRESENT', ident)
                elif col == 'customer_analytics_reports' or origin == 'analytics_platform':
                    ident = item.get('email') or item.get('user_id')
                    has_pii = bool(item.get('email') or item.get('user_id') or item.get('phone') or item.get('email_hash'))
                    st = 'PRESENT' if has_pii else 'ANONYMIZED'
                    self.add_obs(fid, cat_at, 'analytics_platform', res_id, 'ANALYTICS_PROFILE', st, ident)
                elif origin == 'integration_management_service' or 'connector' in fpath:
                    ident = item.get('customer_email') or item.get('customer_reference')
                    st = 'ACTIVE' if item.get('enabled') else 'DISABLED'
                    self.add_obs(fid, cat_at, 'integration_service', res_id, 'DATA_FLOW', st, ident)
                elif origin == 'security_audit_service' or 'security_audit' in fpath:
                    ident = item.get('subject_reference')
                    self.add_obs(fid, cat_at, 'security_service', res_id, 'SECURITY_AUDIT_LOG', 'PRESENT', ident)

    def _parse_sql(self, fid, fpath, cat_at, origin):
        with open(fpath, 'r', encoding='utf-8') as f:
            content = f.read()

        insert_matches = re.finditer(r'INSERT INTO ["\']?(\w+)["\']?\s+VALUES\s*\((.*?)\);', content, re.DOTALL | re.IGNORECASE)
        for m in insert_matches:
            tbl = m.group(1).lower()
            vals_str = m.group(2)
            
            vals = []
            for token in re.finditer(r"'(.*?)'|NULL|(\d+)", vals_str):
                if token.group(0) == 'NULL':
                    vals.append(None)
                elif token.group(1) is not None:
                    vals.append(token.group(1))
                else:
                    vals.append(token.group(2))
            
            if not vals:
                continue

            res_id = vals[0]

            # 1. Generic customer_data_* tables (resource_id, origin_system, collection_name, record_json, updated_at)
            if tbl.startswith('customer_data_'):
                if len(vals) >= 4 and vals[3] and vals[3].strip().startswith('{'):
                    try:
                        record_json = json.loads(vals[3])
                        sys_id = vals[1]
                        ident = record_json.get('email') or record_json.get('user_id') or record_json.get('customer_reference')
                        
                        st = 'PRESENT'
                        if sys_id == 'analytics_platform':
                            has_pii = bool(record_json.get('email') or record_json.get('phone') or record_json.get('email_hash'))
                            st = 'PRESENT' if has_pii else 'ANONYMIZED'
                        elif sys_id == 'backup_service':
                            st = 'ACTIVE' if record_json.get('restore_allowed') else 'BLOCKED'
                        elif sys_id == 'integration_service':
                            st = 'ACTIVE' if record_json.get('enabled') else 'DISABLED'
                        elif sys_id == 'support_platform':
                            st = 'PRESENT'
                        elif sys_id == 'identity_service':
                            st = 'REDACTED' if not record_json.get('email') else 'PRESENT'

                        cat = 'USER_PROFILE' if sys_id == 'account_service' else (
                            'SEARCH_INDEX_ENTRY' if sys_id == 'search_service' else (
                            'ANALYTICS_PROFILE' if sys_id == 'analytics_platform' else (
                            'SUPPORT_MESSAGE' if sys_id == 'support_platform' else (
                            'USER_EXPORT' if sys_id == 'export_service' else (
                            'DATA_FLOW' if sys_id == 'integration_service' else (
                            'BACKUP_ARCHIVE' if sys_id == 'backup_service' else (
                            'SECURITY_AUDIT_LOG' if sys_id == 'security_service' else (
                            'ACCOUNT_TOMBSTONE' if sys_id == 'identity_service' else 'OTHER'))))))))

                        self.add_obs(fid, cat_at, sys_id, res_id, cat, st, ident)
                        # Also add email_hash or phone if present
                        if record_json.get('email_hash'):
                            self.add_obs(fid, cat_at, sys_id, res_id, cat, st, record_json['email_hash'])
                        continue
                    except:
                        pass

            # 2. Specific single-purpose tables
            if tbl in ('customer_profiles', 'customer_profiles_failover_replica', 'customer_profiles_primary'):
                ident = None
                for v in vals[1:]:
                    if v and ('@' in str(v) or str(v).startswith('user_')):
                        ident = v
                        break
                st = 'PRESENT'
                self.add_obs(fid, cat_at, 'account_service', res_id, 'USER_PROFILE', st, ident)

            elif tbl in ('customer_search_documents', 'search_documents_primary'):
                ident = None
                for v in vals[1:]:
                    if v and ('@' in str(v) or str(v).startswith('user_')):
                        ident = v
                        break
                self.add_obs(fid, cat_at, 'search_service', res_id, 'SEARCH_INDEX_ENTRY', 'PRESENT', ident)

            elif tbl == 'customer_analytics_profiles':
                ident = None
                for v in vals[1:5]:
                    if v and ('@' in str(v) or str(v).startswith('user_')):
                        ident = v
                        break
                st = 'PRESENT' if ident else 'ANONYMIZED'
                self.add_obs(fid, cat_at, 'analytics_platform', res_id, 'ANALYTICS_PROFILE', st, ident)
                # If email_hash is 5th column
                if len(vals) > 4 and vals[4] and len(vals[4]) == 64:
                    self.add_obs(fid, cat_at, 'analytics_platform', res_id, 'ANALYTICS_PROFILE', st, vals[4])

            elif tbl == 'support_records':
                ident = None
                for v in vals[1:5]:
                    if v and ('@' in str(v) or str(v).startswith('user_')):
                        ident = v
                        break
                st = 'PRESENT' if ident else 'REDACTED'
                self.add_obs(fid, cat_at, 'support_platform', res_id, 'SUPPORT_MESSAGE', st, ident)

            elif tbl == 'customer_exports':
                ident = None
                for v in vals[1:4]:
                    if v and ('@' in str(v) or str(v).startswith('user_')):
                        ident = v
                        break
                self.add_obs(fid, cat_at, 'export_service', res_id, 'USER_EXPORT', 'PRESENT', ident)

            elif tbl == 'connector_subscriptions':
                ident = None
                for v in vals[1:3]:
                    if v and ('@' in str(v) or str(v).startswith('user_')):
                        ident = v
                        break
                st = 'ACTIVE' if (len(vals) > 4 and str(vals[4]) == '1') else 'DISABLED'
                self.add_obs(fid, cat_at, 'integration_service', res_id, 'DATA_FLOW', st, ident)

            elif tbl == 'backup_restore_entries':
                ident = None
                for v in vals[1:3]:
                    if v and ('@' in str(v) or str(v).startswith('user_')):
                        ident = v
                        break
                st = 'ACTIVE' if (len(vals) > 4 and str(vals[4]) == '1') else 'BLOCKED'
                self.add_obs(fid, cat_at, 'backup_service', res_id, 'BACKUP_ARCHIVE', st, ident)

            elif tbl == 'security_audit_records':
                ident = vals[1] if len(vals) > 1 else None
                self.add_obs(fid, cat_at, 'security_service', res_id, 'SECURITY_AUDIT_LOG', 'PRESENT', ident)

    def _parse_log(self, fid, fpath, cat_at, origin):
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        traces = defaultdict(list)
        standalone_lines = []

        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue

            # Check for trace_id
            m_tr = re.search(r'trace_id[=: "]+([a-zA-Z0-9_\-]+)', line_str)
            if m_tr:
                traces[m_tr.group(1)].append(line_str)
            else:
                standalone_lines.append(line_str)

        # 1. Process traces
        for tr_id, tr_lines in traces.items():
            combined = ' '.join(tr_lines)
            
            # Resource ID
            m_res = re.search(r'resource_id[=: "]+([a-zA-Z0-9_\-]+)', combined)
            if not m_res:
                continue
            res_id = m_res.group(1).strip('"\'')

            # Service
            m_sys = re.search(r'service[=: "]+([a-zA-Z0-9_]+)', combined)
            sys_id = m_sys.group(1) if m_sys else None
            if sys_id == 'support_replica':
                sys_id = 'support_platform'
            if not sys_id or sys_id in ('log_router', 'feature_flags'):
                if res_id.startswith('account_'): sys_id = 'account_service'
                elif res_id.startswith('search_'): sys_id = 'search_service'
                elif res_id.startswith('analytics_'): sys_id = 'analytics_platform'
                elif res_id.startswith('support_'): sys_id = 'support_platform'
                elif res_id.startswith('export_'): sys_id = 'export_service'
                elif res_id.startswith('data_flow_'): sys_id = 'integration_service'
                elif res_id.startswith('backup_'): sys_id = 'backup_service'
                elif res_id.startswith('audit_record_'): sys_id = 'security_service'
                elif res_id.startswith('tombstone_'): sys_id = 'identity_service'

            # Identifiers: gather all matching keys
            idents = set()
            for m in re.finditer(r'(?:lookup_key|correlation_key|subject_key|customer_email|email|owner_email|requester_email)[=: "]+([a-zA-Z0-9_\-\.@]+)', combined):
                val = m.group(1).strip('"\'')
                if val and val != 'null':
                    idents.add(val)
            for m in re.finditer(r'\b(user_\d+)\b', combined):
                idents.add(m.group(1))

            # State
            st = 'PRESENT'
            if 'http_status=404' in combined or 'rows=0' in combined or 'rows="0"' in combined or 'NOT_FOUND' in combined or 'status_code="404"' in combined:
                st = 'ABSENT'
            elif 'marker_found=false' in combined:
                st = 'PRESENT'
            elif 'restore_allowed=false' in combined or 'deletion_block=true' in combined or 'BLOCKED' in combined:
                st = 'BLOCKED'
            elif 'restore_allowed=true' in combined or 'deletion_block=false' in combined or 'eligible=true' in combined:
                st = 'ACTIVE'
            elif 'connector_state=disabled' in combined or 'enabled=false' in combined or 'enabled="0"' in combined or 'DISABLED' in combined:
                st = 'DISABLED'
            elif 'connector_state=active' in combined or 'enabled=true' in combined or 'enabled="1"' in combined:
                st = 'ACTIVE'
            elif 'customer_reference=null' in combined and 'email=null' in combined:
                st = 'ANONYMIZED'

            cat = 'USER_PROFILE' if sys_id == 'account_service' else (
                'SEARCH_INDEX_ENTRY' if sys_id == 'search_service' else (
                'ANALYTICS_PROFILE' if sys_id == 'analytics_platform' else (
                'SUPPORT_MESSAGE' if sys_id == 'support_platform' else (
                'USER_EXPORT' if sys_id == 'export_service' else (
                'DATA_FLOW' if sys_id == 'integration_service' else (
                'BACKUP_ARCHIVE' if sys_id == 'backup_service' else (
                'SECURITY_AUDIT_LOG' if sys_id == 'security_service' else (
                'ACCOUNT_TOMBSTONE' if sys_id == 'identity_service' else 'OTHER'))))))))

            for ident in idents:
                self.add_obs(fid, cat_at, sys_id, res_id, cat, st, ident)

        # 2. Process standalone lines
        for line in standalone_lines:
            m_res = re.search(r'resource_id[=: "]+([a-zA-Z0-9_\-]+)', line)
            if not m_res:
                continue
            res_id = m_res.group(1).strip('"\'')

            m_sys = re.search(r'service[=: "]+([a-zA-Z0-9_]+)', line)
            sys_id = m_sys.group(1) if m_sys else None
            if not sys_id or sys_id in ('log_router', 'feature_flags'):
                if res_id.startswith('account_'): sys_id = 'account_service'
                elif res_id.startswith('search_'): sys_id = 'search_service'
                elif res_id.startswith('analytics_'): sys_id = 'analytics_platform'
                elif res_id.startswith('support_'): sys_id = 'support_platform'
                elif res_id.startswith('export_'): sys_id = 'export_service'
                elif res_id.startswith('data_flow_'): sys_id = 'integration_service'
                elif res_id.startswith('backup_'): sys_id = 'backup_service'
                elif res_id.startswith('audit_record_'): sys_id = 'security_service'
                elif res_id.startswith('tombstone_'): sys_id = 'identity_service'

            ident = None
            m_email = re.search(r'([a-zA-Z0-9_\-\.]+@[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,})', line)
            if m_email:
                ident = m_email.group(1)
            else:
                m_uid = re.search(r'\b(user_\d+)\b', line)
                if m_uid:
                    ident = m_uid.group(1)

            st = 'PRESENT'
            if '404' in line or 'rows="0"' in line or 'rows=0' in line or 'NOT_FOUND' in line:
                st = 'ABSENT'
            elif 'restore_allowed=false' in line or 'BLOCKED' in line:
                st = 'BLOCKED'
            elif 'connector_state=disabled' in line or 'enabled=false' in line or 'DISABLED' in line:
                st = 'DISABLED'
            elif 'customer_reference=null' in line and 'email=null' in line:
                st = 'ANONYMIZED'

            cat = 'USER_PROFILE' if sys_id == 'account_service' else (
                'SEARCH_INDEX_ENTRY' if sys_id == 'search_service' else (
                'ANALYTICS_PROFILE' if sys_id == 'analytics_platform' else (
                'SUPPORT_MESSAGE' if sys_id == 'support_platform' else (
                'USER_EXPORT' if sys_id == 'export_service' else (
                'DATA_FLOW' if sys_id == 'integration_service' else (
                'BACKUP_ARCHIVE' if sys_id == 'backup_service' else (
                'SECURITY_AUDIT_LOG' if sys_id == 'security_service' else (
                'ACCOUNT_TOMBSTONE' if sys_id == 'identity_service' else 'OTHER'))))))))

            self.add_obs(fid, cat_at, sys_id, res_id, cat, st, ident)

    def _parse_binaries(self, fid, fpath, cat_at, origin):
        # PDFs:
        if fid == 'evidence_18': # account_history_report_20260718.pdf
            self.add_obs(fid, cat_at, 'account_service', 'account_18', 'USER_PROFILE', 'PRESENT', 'ingrid.dahl@outlook.com')
        elif fid == 'evidence_27': # legal_retention_register_20260529.pdf
            for u in ['user_08', 'user_12', 'user_17', 'user_21', 'user_24', 'user_29']:
                self.add_obs(fid, cat_at, 'finance_operations', f'legal_hold_{u}', 'LEGAL_HOLD_RECORD', 'PRESENT', u)
        elif fid == 'evidence_55': # security_retention_extract.pdf
            self.add_obs(fid, cat_at, 'security_service', 'audit_record_003', 'SECURITY_AUDIT_LOG', 'PRESENT', 'user_03')
        elif fid == 'evidence_58': # delivery_correction_attachment.pdf
            self.add_obs(fid, cat_at, 'support_platform', 'support_001', 'SUPPORT_ATTACHMENT', 'PRESENT', 'priya.raman@gmail.com')

        # PNGs:
        elif fid == 'evidence_04': # account_admin_console_20260926.png
            self.add_obs(fid, cat_at, 'account_service', 'account_5762', 'USER_PROFILE', 'PRESENT', 'haruka.s1838@zoho.com')
            self.add_obs(fid, cat_at, 'support_platform', 'support_9538', 'SUPPORT_MESSAGE', 'PRESENT', 'haruka.s1838@zoho.com')
        elif fid == 'evidence_09': # search_index_inspector_20260901.png
            self.add_obs(fid, cat_at, 'search_service', 'search_428', 'SEARCH_INDEX_ENTRY', 'PRESENT', 'g.silva76@gmail.com')
        elif fid == 'evidence_14': # connector_management_console_20260807.png
            self.add_obs(fid, cat_at, 'integration_service', 'data_flow_1121', 'DATA_FLOW', 'ACTIVE', 'jain.aditi@gmail.com')
            self.add_obs(fid, cat_at, 'integration_service', 'data_flow_9846', 'DATA_FLOW', 'ACTIVE', 'lucia-torres@gmail.com')
        elif fid == 'evidence_19': # analytics_profile_view_20260713.png
            self.add_obs(fid, cat_at, 'analytics_platform', 'analytics_7438', 'ANALYTICS_PROFILE', 'PRESENT', 'darwish.omar@icloud.com')
        elif fid == 'evidence_23': # customer_export_console_20260618.png
            self.add_obs(fid, cat_at, 'export_service', 'export_1260', 'USER_EXPORT', 'PRESENT', 'ingrid.dahl@outlook.com')
        elif fid == 'evidence_28': # support_ticket_console_20260524.png
            self.add_obs(fid, cat_at, 'support_platform', 'support_1034', 'SUPPORT_MESSAGE', 'PRESENT', 'kagyeman8947@fastmail.com')
        elif fid == 'evidence_32': # backup_restore_console_20260429.png
            self.add_obs(fid, cat_at, 'backup_service', 'backup_9287', 'BACKUP_ARCHIVE', 'ACTIVE', 'areed1433@gmail.com')
            self.add_obs(fid, cat_at, 'backup_service', 'backup_9291', 'BACKUP_ARCHIVE', 'ACTIVE', 'bluepeakco@outlook.com')
        elif fid == 'evidence_37': # security_audit_explorer_20260905.png
            for i in range(1, 7):
                self.add_obs(fid, cat_at, 'security_service', f'audit_record_00{i}', 'SECURITY_AUDIT_LOG', 'PRESENT', 'user_03')
        elif fid == 'evidence_42': # deleted_account_reference_20260310.png
            self.add_obs(fid, cat_at, 'identity_service', 'tombstone_user_17', 'ACCOUNT_TOMBSTONE', 'REDACTED', 'user_17')
        elif fid == 'evidence_46': # object_storage_browser_20260213.png
            self.add_obs(fid, cat_at, 'support_platform', 'delivery_confirmation_19.pdf', 'SUPPORT_ATTACHMENT', 'PRESENT')
        elif fid == 'evidence_60': # marketing_profile_console.png
            self.add_obs(fid, cat_at, 'marketing_platform', 'marketing_001', 'MARKETING_PROFILE', 'PRESENT', 'sj.park@naver.com')

if __name__ == '__main__':
    indexer = EvidenceIndexer()
    indexer.parse_all()
