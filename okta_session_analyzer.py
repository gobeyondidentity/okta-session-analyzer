import pandas as pd
import argparse
import math

def haversine(lon1, lat1, lon2, lat2):
    # Convert latitude and longitude from degrees to radians
    lon1, lat1, lon2, lat2 = map(math.radians, [lon1, lat1, lon2, lat2])
    
    # Haversine formula
    dlon = lon2 - lon1 
    dlat = lat2 - lat1 
    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    r = 6371  # Radius of Earth in kilometers
    return r * c

def bucket_sessions(csv_file):
    # Read the CSV file into a pandas DataFrame
    df = pd.read_csv(csv_file, parse_dates=['timestamp'], low_memory=False)
    
    # Check if the necessary columns exist in the DataFrame
    required_columns = ['authentication_context.external_session_id', 'client.geographical_context.country']
    for col in required_columns:
        if col not in df.columns:
            raise ValueError(f'The specified column {col} does not exist in the CSV file')
    
    # Filter out rows based on specified conditions
    df = df[
        df['authentication_context.external_session_id'].notna() &
        df['authentication_context.external_session_id'].ne('') &
        df['authentication_context.external_session_id'].ne('unknown') &
        df['client.geographical_context.country'].notna() &
        df['client.geographical_context.country'].ne('')
    ]
    
    # Group the log lines by 'authentication_context.external_session_id'
    grouped = df.groupby('authentication_context.external_session_id')
    
    # Create a dictionary to hold the sessions
    sessions = {}
    
    # Iterate over each group (i.e., each unique external_session_id)
    for name, group in grouped:
        # The name variable contains the unique external_session_id value
        # The group variable contains all log lines with the same external_session_id
        sessions[name] = group.to_dict(orient='records')
    
    return sessions

def analyze_session_fast_travel(session_id, session_logs, fast_travel_threshold):
    fast_travel_instances = []
    df = pd.DataFrame(session_logs)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values(by='timestamp', ascending=True)

    for i in range(len(df) - 1):
        # Get coordinates and timestamps of consecutive log entries
        lon1, lat1, uuid1 = df.at[i, 'client.geographical_context.geolocation.lon'], df.at[i, 'client.geographical_context.geolocation.lat'], df.at[i, 'uuid']
        lon2, lat2, uuid2 = df.at[i+1, 'client.geographical_context.geolocation.lon'], df.at[i+1, 'client.geographical_context.geolocation.lat'], df.at[i+1, 'uuid']
        time1, time2 = pd.to_datetime(df.at[i, 'timestamp']), pd.to_datetime(df.at[i+1, 'timestamp'])

        # Calculate distance, time difference, and speed
        distance = haversine(lon1, lat1, lon2, lat2)  # Distance in kilometers
        time_diff = (time2 - time1).seconds / 3600  # Time difference in hours
        if time_diff == 0:  # Prevent division by zero
            continue
        speed = distance / time_diff  # Speed in km/h

        if speed > fast_travel_threshold:
            fast_travel_instances.append((session_id, i, i+1, uuid1, uuid2, distance, speed))

    return fast_travel_instances

def detect_high_frequency_event(session_id, log_lines, event_type, frequency_threshold):
    high_frequency_instances = []
    # Convert list of log lines to a DataFrame for easier processing
    df = pd.DataFrame(log_lines)
    df['timestamp'] = pd.to_datetime(df['timestamp'])  # Ensure the timestamp column is in datetime format
    df = df.sort_values(by='timestamp', ascending=True)  # Sort the DataFrame by the timestamp column

    # Filter the DataFrame for the specified event_type
    event_df = df[df['event_type'] == event_type]
    
    # Count the occurrences of the specified event_type
    event_count = len(event_df)
        
    # Check for high frequency
    if event_count >= frequency_threshold:
        high_frequency_instances.append((session_id, event_count))
    return high_frequency_instances


def analyze_user_sessions(csv_file_path, fast_travel_threshold, push_notification_threshold, unauthorized_acccess_attempts_threshold):
    sessions = bucket_sessions(csv_file_path)

    # Iterate through each session in the sessions dictionary
    for session_id, log_lines in sessions.items():

        user_agents = {log_line['client.user_agent.raw_user_agent'] for log_line in log_lines}
        ip_addresses = {log_line['client.ip_address'] for log_line in log_lines}
        
        fast_travel_instances = analyze_session_fast_travel(session_id, log_lines, fast_travel_threshold)
        push_fatigue_instances = detect_high_frequency_event(session_id, log_lines, 'system.push.send_factor_verify_push', push_notification_threshold)
        push_fatigue_deny_instances = detect_high_frequency_event(session_id, log_lines,'user.mfa.okta_verify.deny_push', 0)
        high_frequency_unauthorized_access = detect_high_frequency_event(session_id, log_lines, 'app.generic.unauth_app_access_attempt', unauthorized_acccess_attempts_threshold)

        if len(user_agents) > 1 and len(ip_addresses) > 1:
            print(f'Session ID: {session_id} has multiple user agents: {", ".join(user_agents)}')
            print(f'Session ID: {session_id} has multiple IP addresses: {", ".join(ip_addresses)}')            
       
        if len(fast_travel_instances) > 0:
            for instance in fast_travel_instances:
                print(f'Session ID: {session_id} Fast travel detected between events {instance[3]} and {instance[4]}: Distance: {instance[5]:.2f} km Speed: {instance[6]:.2f} km/h')
        
        if len(push_fatigue_instances) > 0:
            push_count = push_fatigue_instances[0][1]
            denied_push_count = push_fatigue_deny_instances[0][1]
            print(f'Session ID: {session_id} has indicators of high frequency MFA push requests, there were {push_count} push requests with {denied_push_count} denials')

        if len(high_frequency_unauthorized_access) > 0:
            attempt_count = high_frequency_unauthorized_access[0][1]
            print(f'Session ID: {session_id} has indicators of high frequency unauthorized application access attempts: {attempt_count}')

def analyze_idp_config_changes(df):
    # Define the event types to filter
    event_types = [
        'system.idp.lifecycle.delete',
        'system.idp.lifecycle.create',
        'system.idp.lifecycle.update',
        'system.idp.lifecycle.deactivate',
        'system.idp.lifecycle.activate'
    ]
    
    # Filter the DataFrame based on the event_type column
    filtered_df = df[df['event_type'].isin(event_types)]

    for index, row in filtered_df.iterrows():
        uuid = row['uuid']
        display_message = row['display_message']
        idp_display_name = row['target0.display_name']
        print(f'Event ID: {uuid} indicates an IDP configuration change: "{display_message}" for "{idp_display_name}"')

def analyze_okta_config_changes(csv_file_path):
    # Read the CSV file
    df = pd.read_csv(csv_file_path, low_memory=False)

    analyze_idp_config_changes(df)
    


def main():
    parser = argparse.ArgumentParser(description='Okta Session Analyzer')
    parser.add_argument('csv_file', help='Path to the CSV file containing Okta event logs.')
    parser.add_argument('--tt', type=float, default=100,
                        help='Threshold distance in km/h to consider as fast travel. Default is 100 km/h.')
    parser.add_argument('--pt', type=int, default=3,
                        help='Threshold for push notifications in a single session. Default is 3')
    parser.add_argument('--aat', type=int, default=1, help="Threshold for unauthorized access attempts in a single session. Default is 1")

    args = parser.parse_args()

    csv_file_path = args.csv_file
    fast_travel_threshold = args.tt
    push_notification_threshold = args.pt
    unauthorized_acccess_attempts_threshold = args.aat

    analyze_user_sessions(csv_file_path, fast_travel_threshold, push_notification_threshold, unauthorized_acccess_attempts_threshold)
    analyze_okta_config_changes(csv_file_path)
    

if __name__ == '__main__':
    main()