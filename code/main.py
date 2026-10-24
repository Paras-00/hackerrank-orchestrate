import sys
sys.stdout.reconfigure(encoding='utf-8')
import os, argparse, json
import pandas as pd

# Support running directly or from repository root
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
code_dir = os.path.dirname(os.path.abspath(__file__))
if code_dir not in sys.path:
    sys.path.insert(0, code_dir)

from auditor import DeletionAuditor

def main():
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists: AI-powered Deletion Audit Agent")
    parser.add_argument('--dataset-dir', default='dataset', help='Path to dataset directory')
    parser.add_argument('--input', default=None, help='Path to requests CSV (default: <dataset-dir>/deletion_requests.csv)')
    parser.add_argument('--output', default='output.csv', help='Path to output CSV (default: output.csv at repo root)')
    args = parser.parse_args()

    input_path = args.input or os.path.join(args.dataset_dir, 'deletion_requests.csv')
    output_path = args.output

    print(f"=== Starting Ghost Data Still Exists Deletion Audit ===")
    print(f"Dataset dir: {args.dataset_dir}")
    print(f"Input file:  {input_path}")
    print(f"Output file: {output_path}")

    if not os.path.exists(input_path):
        print(f"Error: input file {input_path} does not exist!")
        sys.exit(1)

    auditor = DeletionAuditor(dataset_dir=args.dataset_dir)
    df_out = auditor.audit_dataset(input_path, output_path)

    # Post-run validation
    print("\n=== Validating Generated output.csv ===")
    if not os.path.exists(output_path):
        print(f"Validation Error: {output_path} does not exist!")
        sys.exit(1)

    df_check = pd.read_csv(output_path)
    expected_cols = ['case_id', 'deletion_status', 'steps_json']
    if list(df_check.columns) != expected_cols:
        print(f"Validation Error: Columns {list(df_check.columns)} do not match expected {expected_cols}!")
        sys.exit(1)

    expected_count = len(pd.read_csv(input_path))
    if len(df_check) != expected_count:
        print(f"Validation Error: Row count {len(df_check)} != expected {expected_count}!")
        sys.exit(1)

    allowed_statuses = {'COMPLETE', 'INCOMPLETE', 'NOT_APPLICABLE'}
    status_counts = df_check['deletion_status'].value_counts().to_dict()
    print(f"Status distribution: {status_counts}")

    for idx, r in df_check.iterrows():
        st = r['deletion_status']
        if st not in allowed_statuses:
            print(f"Validation Error at row {idx} ({r['case_id']}): Invalid status '{st}'")
            sys.exit(1)
        try:
            steps = json.loads(r['steps_json'])
            if not isinstance(steps, list):
                print(f"Validation Error at row {idx} ({r['case_id']}): steps_json is not an array!")
                sys.exit(1)
            if st == 'NOT_APPLICABLE' and len(steps) != 0:
                print(f"Validation Error at row {idx} ({r['case_id']}): NOT_APPLICABLE must have empty steps_json!")
                sys.exit(1)
            for s_idx, step in enumerate(steps):
                if step.get('step_no') != s_idx + 1:
                    print(f"Validation Error at row {idx} ({r['case_id']}): step_no {step.get('step_no')} != {s_idx + 1}!")
                    sys.exit(1)
        except Exception as e:
            print(f"Validation Error at row {idx} ({r['case_id']}): Invalid JSON: {e}")
            sys.exit(1)

    print(f"Validation successful! {len(df_check)} rows verified and ready for evaluation/submission.")

if __name__ == '__main__':
    main()
