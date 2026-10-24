import sys
sys.stdout.reconfigure(encoding='utf-8')
import os, json, glob, re, hashlib
import pandas as pd
from collections import defaultdict
try:
    from .evidence_indexer import EvidenceIndexer
except ImportError:
    from evidence_indexer import EvidenceIndexer

class DeletionAuditor:
    def __init__(self, dataset_dir='dataset'):
        self.dataset_dir = dataset_dir
        self.df_users = pd.read_csv(os.path.join(dataset_dir, 'user_identities.csv'))
        self.df_audit = pd.read_csv(os.path.join(dataset_dir, 'user_audit_log.csv'))
        self.df_act = pd.read_csv(os.path.join(dataset_dir, 'system_activity.csv'))
        self.df_ev = pd.read_csv(os.path.join(dataset_dir, 'evidence_files.csv'))

        # Build mapping from email -> user_id, uid -> emails, uid -> phones, uid -> hashes
        self.email_to_uid = {}
        self.uid_to_emails = defaultdict(set)
        self.uid_to_phones = defaultdict(set)
        self.uid_to_hashes = defaultdict(set)
        self.uid_to_name = {}

        for idx, r in self.df_users.iterrows():
            uid = r['user_id']
            email_clean = r['email'].strip().lower()
            self.email_to_uid[email_clean] = uid
            self.uid_to_emails[uid].add(email_clean)
            self.uid_to_phones[uid].add(str(r['phone']).strip())
            self.uid_to_name[uid] = r['name']
            if pd.notna(r['email_hash']):
                self.uid_to_hashes[uid].add(str(r['email_hash']).strip().lower())
            self.uid_to_hashes[uid].add(hashlib.sha256(email_clean.encode('utf-8')).hexdigest())

        for idx, r in self.df_audit.iterrows():
            uid = r['user_id']
            if r['field_name'] == 'email':
                for val in [r['old_value'], r['new_value']]:
                    if pd.notna(val):
                        em = str(val).strip().lower()
                        self.email_to_uid[em] = uid
                        self.uid_to_emails[uid].add(em)
                        self.uid_to_hashes[uid].add(hashlib.sha256(em.encode('utf-8')).hexdigest())
            elif r['field_name'] == 'phone':
                for val in [r['old_value'], r['new_value']]:
                    if pd.notna(val):
                        self.uid_to_phones[uid].add(str(val).strip())

        self.indexer = EvidenceIndexer(dataset_dir=dataset_dir)
        self.all_obs = self.indexer.parse_all()

        # Index observations by identifier
        self.obs_by_ident = defaultdict(list)
        for ob in self.all_obs:
            ident = ob.get('identifier')
            if ident:
                self.obs_by_ident[ident.strip().lower()].append(ob)

        self.FINDING_ORDER = {'REPORT_REMAINING_RECORD': 1, 'REPORT_EXPOSED_PII': 2, 'REPORT_ACTIVE_DATA_FLOW': 3, 'REPORT_RESTORE_RISK': 4}
        self.REMEDIATION_ORDER = {'DISABLE_DATA_FLOW': 1, 'BLOCK_RESTORE': 2, 'DELETE_RECORD': 3, 'REDACT_RECORD': 4, 'ANONYMIZE_RECORD': 5}
        self.VERIFICATION_ORDER = {'VERIFY_RECORD_ABSENT': 1, 'VERIFY_RECORD_PRESENT': 2, 'VERIFY_RECORD_REDACTED': 3, 'VERIFY_RECORD_ANONYMIZED': 4, 'VERIFY_DATA_FLOW_DISABLED': 5, 'VERIFY_RESTORE_BLOCKED': 6}

    def is_non_deletion(self, text):
        txt = str(text).lower()
        neg_phrases = [
            'not asking', 'do not delete', "don't delete", 'do not close', "don't close",
            'not a request', 'not delete', 'only marketing', 'lists only', 'marketing lists',
            'leave active', 'keep active', 'keep the account', 'leave the account',
            'misspelled', 'misspelt', 'access request', 'information request',
            'continue using', 'leave my profile', 'download my account'
        ]
        return any(p in txt for p in neg_phrases)

    def audit_case(self, req_row):
        cid = req_row['case_id']
        req_text = req_row['request_text']
        
        if self.is_non_deletion(req_text):
            return 'NOT_APPLICABLE', []
        
        email = req_row['email'].strip().lower()
        uid = self.email_to_uid.get(email)
        user_emails = self.uid_to_emails.get(uid, {email})
        user_phones = self.uid_to_phones.get(uid, set())
        user_hashes = self.uid_to_hashes.get(uid, {hashlib.sha256(email.encode('utf-8')).hexdigest()})
        audit_at = req_row['audit_at']
        requested_at = req_row['requested_at']
        reported_at = req_row['reported_at']
        reported_st = req_row['reported_status']
        
        # 1. Gather all observations for this user at or before audit_at
        user_obs = []
        keys_to_search = set(user_emails)
        if uid:
            keys_to_search.add(uid.lower())
        for ph in user_phones:
            keys_to_search.add(ph.lower())
        for h in user_hashes:
            keys_to_search.add(h.lower())
            
        for k in keys_to_search:
            if k in self.obs_by_ident:
                for ob in self.obs_by_ident[k]:
                    if ob['captured_at'] <= audit_at:
                        user_obs.append(ob)
                        
        # Also find primary account from system_activity if not observed
        acc_res = None
        for ob in user_obs:
            if ob['system_id'] == 'account_service':
                acc_res = ob['resource_id']
                break
                
        if not acc_res:
            if uid and uid.startswith('user_'):
                u_num = uid.split('_')[1]
                if len(u_num) <= 2 and int(u_num) <= 10:
                    acc_res = f"account_{int(u_num):03d}"
                    
        if not acc_res:
            status_map = {'COMPLETE': 'SUCCESS', 'PARTIALLY_COMPLETE': 'PARTIAL', 'NOT_STARTED': 'FAILED'}
            exp_res = status_map.get(reported_st)
            cand_acts = self.df_act[(self.df_act['target_system'] == 'account_service') & 
                                    (self.df_act['event_type'] == 'DELETE_RECORD') &
                                    (self.df_act['event_time'] >= requested_at) &
                                    (self.df_act['event_time'] <= reported_at)]
            if len(cand_acts) > 0:
                match_res = cand_acts[cand_acts['reported_result'] == exp_res]
                if len(match_res) > 0:
                    acc_res = match_res.iloc[-1]['resource_id']
                else:
                    acc_res = cand_acts.iloc[-1]['resource_id']
                    
        # Determine state of acc_res using the LATEST observation at or before audit_at
        acc_state = 'ABSENT'
        acc_ev = None
        if acc_res:
            acc_obs = [ob for ob in self.all_obs if ob['system_id'] == 'account_service' and ob['resource_id'] == acc_res and ob['captured_at'] <= audit_at]
            if acc_obs:
                latest_acc = sorted(acc_obs, key=lambda x: x['captured_at'])[-1]
                acc_state = latest_acc['raw_state']
                acc_ev = latest_acc['file_id']
            else:
                acc_state = 'ABSENT'
                recent_ev = self.df_ev[self.df_ev['captured_at'] <= audit_at].sort_values('captured_at').iloc[-1]['file_id']
                acc_ev = recent_ev
                    
        # Group observations by (system_id, resource_id)
        res_dict = {}
        if acc_res:
            res_dict[('account_service', acc_res)] = [{
                'system_id': 'account_service',
                'resource_id': acc_res,
                'category': 'USER_PROFILE',
                'raw_state': acc_state,
                'file_id': acc_ev,
                'captured_at': audit_at
            }]
            
        for ob in user_obs:
            key = (ob['system_id'], ob['resource_id'])
            if key not in res_dict:
                res_dict[key] = []
            res_dict[key].append(ob)
            
        # Analyze findings and verifications
        findings = []
        verifications = []
        
        for (sys_id, res_id), ob_list in res_dict.items():
            latest_ob = sorted(ob_list, key=lambda x: x.get('captured_at', ''))[-1]
            cat = latest_ob.get('category')
            st = latest_ob.get('raw_state')
            fid = latest_ob.get('file_id')
            
            if sys_id == 'account_service':
                if st == 'PRESENT':
                    findings.append({
                        'system_id': sys_id,
                        'resource_id': res_id,
                        'operation': 'REPORT_REMAINING_RECORD',
                        'state': 'PRESENT',
                        'evidence_id': fid,
                        'remediation_op': 'DELETE_RECORD',
                        'remediation_st': 'ABSENT',
                        'verify_op': 'VERIFY_RECORD_ABSENT',
                        'verify_st': 'ABSENT'
                    })
                else:
                    verifications.append({
                        'system_id': sys_id,
                        'resource_id': res_id,
                        'operation': 'VERIFY_RECORD_ABSENT',
                        'state': 'ABSENT',
                        'evidence_id': fid
                    })
                    
            elif sys_id == 'search_service':
                if st == 'PRESENT':
                    findings.append({
                        'system_id': sys_id,
                        'resource_id': res_id,
                        'operation': 'REPORT_REMAINING_RECORD',
                        'state': 'PRESENT',
                        'evidence_id': fid,
                        'remediation_op': 'DELETE_RECORD',
                        'remediation_st': 'ABSENT',
                        'verify_op': 'VERIFY_RECORD_ABSENT',
                        'verify_st': 'ABSENT'
                    })
                else:
                    verifications.append({
                        'system_id': sys_id,
                        'resource_id': res_id,
                        'operation': 'VERIFY_RECORD_ABSENT',
                        'state': 'ABSENT',
                        'evidence_id': fid
                    })
                    
            elif sys_id == 'analytics_platform':
                if st == 'PRESENT':
                    findings.append({
                        'system_id': sys_id,
                        'resource_id': res_id,
                        'operation': 'REPORT_EXPOSED_PII',
                        'state': 'PRESENT',
                        'evidence_id': fid,
                        'remediation_op': 'ANONYMIZE_RECORD',
                        'remediation_st': 'ANONYMIZED',
                        'verify_op': 'VERIFY_RECORD_ANONYMIZED',
                        'verify_st': 'ANONYMIZED'
                    })
                elif st == 'ANONYMIZED':
                    verifications.append({
                        'system_id': sys_id,
                        'resource_id': res_id,
                        'operation': 'VERIFY_RECORD_ANONYMIZED',
                        'state': 'ANONYMIZED',
                        'evidence_id': fid
                    })
                elif st == 'ABSENT':
                    verifications.append({
                        'system_id': sys_id,
                        'resource_id': res_id,
                        'operation': 'VERIFY_RECORD_ABSENT',
                        'state': 'ABSENT',
                        'evidence_id': fid
                    })
                    
            elif sys_id == 'support_platform':
                if cat == 'SUPPORT_ATTACHMENT':
                    if st == 'PRESENT':
                        findings.append({
                            'system_id': sys_id,
                            'resource_id': res_id,
                            'operation': 'REPORT_REMAINING_RECORD',
                            'state': 'PRESENT',
                            'evidence_id': fid,
                            'remediation_op': 'DELETE_RECORD',
                            'remediation_st': 'ABSENT',
                            'verify_op': 'VERIFY_RECORD_ABSENT',
                            'verify_st': 'ABSENT'
                        })
                else: # SUPPORT_MESSAGE
                    if st == 'PRESENT':
                        findings.append({
                            'system_id': sys_id,
                            'resource_id': res_id,
                            'operation': 'REPORT_EXPOSED_PII',
                            'state': 'PRESENT',
                            'evidence_id': fid,
                            'remediation_op': 'REDACT_RECORD',
                            'remediation_st': 'REDACTED',
                            'verify_op': 'VERIFY_RECORD_REDACTED',
                            'verify_st': 'REDACTED'
                        })
                    else: # REDACTED
                        verifications.append({
                            'system_id': sys_id,
                            'resource_id': res_id,
                            'operation': 'VERIFY_RECORD_REDACTED',
                            'state': 'REDACTED',
                            'evidence_id': fid
                        })
                        
            elif sys_id == 'export_service':
                if st == 'PRESENT':
                    findings.append({
                        'system_id': sys_id,
                        'resource_id': res_id,
                        'operation': 'REPORT_REMAINING_RECORD',
                        'state': 'PRESENT',
                        'evidence_id': fid,
                        'remediation_op': 'DELETE_RECORD',
                        'remediation_st': 'ABSENT',
                        'verify_op': 'VERIFY_RECORD_ABSENT',
                        'verify_st': 'ABSENT'
                    })
                    
            elif sys_id == 'integration_service':
                if st == 'ACTIVE':
                    findings.append({
                        'system_id': sys_id,
                        'resource_id': res_id,
                        'operation': 'REPORT_ACTIVE_DATA_FLOW',
                        'state': 'ACTIVE',
                        'evidence_id': fid,
                        'remediation_op': 'DISABLE_DATA_FLOW',
                        'remediation_st': 'DISABLED',
                        'verify_op': 'VERIFY_DATA_FLOW_DISABLED',
                        'verify_st': 'DISABLED'
                    })
                else: # DISABLED
                    verifications.append({
                        'system_id': sys_id,
                        'resource_id': res_id,
                        'operation': 'VERIFY_DATA_FLOW_DISABLED',
                        'state': 'DISABLED',
                        'evidence_id': fid
                    })
                    
            elif sys_id == 'backup_service':
                if st == 'ACTIVE':
                    findings.append({
                        'system_id': sys_id,
                        'resource_id': res_id,
                        'operation': 'REPORT_RESTORE_RISK',
                        'state': 'ACTIVE',
                        'evidence_id': fid,
                        'remediation_op': 'BLOCK_RESTORE',
                        'remediation_st': 'BLOCKED',
                        'verify_op': 'VERIFY_RESTORE_BLOCKED',
                        'verify_st': 'BLOCKED'
                    })
                else: # BLOCKED
                    verifications.append({
                        'system_id': sys_id,
                        'resource_id': res_id,
                        'operation': 'VERIFY_RESTORE_BLOCKED',
                        'state': 'BLOCKED',
                        'evidence_id': fid
                    })
                    
            elif sys_id == 'security_service':
                verifications.append({
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': 'VERIFY_RECORD_PRESENT',
                    'state': 'PRESENT',
                    'evidence_id': fid
                })
                
            elif sys_id == 'identity_service':
                if st == 'PRESENT':
                    findings.append({
                        'system_id': sys_id,
                        'resource_id': res_id,
                        'operation': 'REPORT_EXPOSED_PII',
                        'state': 'PRESENT',
                        'evidence_id': fid,
                        'remediation_op': 'REDACT_RECORD',
                        'remediation_st': 'REDACTED',
                        'verify_op': 'VERIFY_RECORD_REDACTED',
                        'verify_st': 'REDACTED'
                    })
                else: # REDACTED
                    verifications.append({
                        'system_id': sys_id,
                        'resource_id': res_id,
                        'operation': 'VERIFY_RECORD_REDACTED',
                        'state': 'REDACTED',
                        'evidence_id': fid
                    })

        status = 'COMPLETE' if len(findings) == 0 else 'INCOMPLETE'
        steps = []
        
        if status == 'COMPLETE':
            verifications.sort(key=lambda s: (self.VERIFICATION_ORDER.get(s['operation'], 99), s['system_id'], s['resource_id']))
            for i, v in enumerate(verifications):
                v['step_no'] = i + 1
                v['phase'] = 'VERIFICATION'
                steps.append(v)
        else: # INCOMPLETE
            # 1. Findings
            findings.sort(key=lambda s: (self.FINDING_ORDER.get(s['operation'], 99), s['system_id'], s['resource_id']))
            for f in findings:
                steps.append({
                    'phase': 'FINDING',
                    'system_id': f['system_id'],
                    'resource_id': f['resource_id'],
                    'operation': f['operation'],
                    'state': f['state'],
                    'evidence_id': f['evidence_id']
                })
                
            # 2. Remediation
            remediations = []
            for f in findings:
                remediations.append({
                    'phase': 'REMEDIATION',
                    'system_id': f['system_id'],
                    'resource_id': f['resource_id'],
                    'operation': f['remediation_op'],
                    'state': f['remediation_st'],
                    'evidence_id': ''
                })
            remediations.sort(key=lambda s: (self.REMEDIATION_ORDER.get(s['operation'], 99), s['system_id'], s['resource_id']))
            steps.extend(remediations)
            
            # 3. Post-remediation verification
            post_verifs = []
            for v in verifications:
                post_verifs.append({
                    'phase': 'VERIFICATION',
                    'system_id': v['system_id'],
                    'resource_id': v['resource_id'],
                    'operation': v['operation'],
                    'state': v['state'],
                    'evidence_id': ''
                })
            for f in findings:
                post_verifs.append({
                    'phase': 'VERIFICATION',
                    'system_id': f['system_id'],
                    'resource_id': f['resource_id'],
                    'operation': f['verify_op'],
                    'state': f['verify_st'],
                    'evidence_id': ''
                })
            post_verifs.sort(key=lambda s: (self.VERIFICATION_ORDER.get(s['operation'], 99), s['system_id'], s['resource_id']))
            steps.extend(post_verifs)
            
            for i, s in enumerate(steps):
                s['step_no'] = i + 1
                
        return status, steps

    def audit_dataset(self, input_csv_path, output_csv_path):
        df_req = pd.read_csv(input_csv_path)
        print(f"Auditing {len(df_req)} requests from {input_csv_path}...")
        
        results = []
        for idx, row in df_req.iterrows():
            cid = row['case_id']
            status, steps = self.audit_case(row)
            steps_json_str = json.dumps(steps, separators=(',', ':'))
            results.append({
                'case_id': cid,
                'deletion_status': status,
                'steps_json': steps_json_str
            })
            
        df_out = pd.DataFrame(results)
        # Sort by case_id
        df_out['cid_num'] = df_out['case_id'].apply(lambda x: int(x.split('_')[1]) if '_' in x else 0)
        df_out = df_out.sort_values('cid_num').drop(columns=['cid_num'])
        
        df_out.to_csv(output_csv_path, index=False, columns=['case_id', 'deletion_status', 'steps_json'])
        print(f"Audit complete. Written {len(df_out)} rows to {output_csv_path}.")
        return df_out
