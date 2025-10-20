"""Zoom IP address and user extractor."""

import base64
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List
import requests


class ZoomExtractor:
    """Extract IP addresses and user information from Zoom meeting participants."""
    
    BASE_URL = "https://api.zoom.us/v2"
    AUTH_URL = "https://zoom.us/oauth/token"
    
    def __init__(self, account_id: str, client_id: str, client_secret: str):
        """
        Initialize Zoom extractor.
        
        Args:
            account_id: Zoom Account ID
            client_id: Zoom OAuth Client ID
            client_secret: Zoom OAuth Client Secret
        """
        self.account_id = account_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None
    
    def _get_access_token(self) -> str:
        """Get OAuth access token using Server-to-Server OAuth."""
        auth_string = f"{self.client_id}:{self.client_secret}"
        auth_bytes = auth_string.encode('ascii')
        auth_base64 = base64.b64encode(auth_bytes).decode('ascii')
        
        headers = {
            'Authorization': f'Basic {auth_base64}',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        data = {
            'grant_type': 'account_credentials',
            'account_id': self.account_id
        }
        
        try:
            response = requests.post(
                self.AUTH_URL,
                headers=headers,
                data=data,
                timeout=30
            )
            response.raise_for_status()
            token_data = response.json()
            return token_data['access_token']
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to get Zoom access token: {str(e)}")
    
    def _ensure_authenticated(self):
        """Ensure we have a valid access token."""
        if not self.access_token:
            self.access_token = self._get_access_token()
    
    def extract_ip_logs(self, days: int = 30) -> List[Dict]:
        """
        Extract IP address logs from Zoom meeting participants.
        
        Uses the Dashboard API (metrics/meetings) to get participant IP addresses
        from past meetings. Requires Business or Business+ plan and
        dashboard_meetings:read:admin scope.
        
        Args:
            days: Number of days to look back
            
        Returns:
            List of dicts with user, email, ip, timestamp, and action
        """
        self._ensure_authenticated()
        logs = []
        
        # Calculate date range
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)
        
        print(f"   ⚠️  Note: Zoom IP extraction requires Business or Business+ plan")
        print(f"   Pro plans do not have access to Dashboard API with IP addresses")
        
        # Step 1: Get list of past meetings
        meetings = self._get_past_meetings(start_date, end_date)
        print(f"   Fetching {len(meetings)} Zoom meetings...")
        
        # Step 2: For each meeting, get participants with IP addresses
        for idx, meeting in enumerate(meetings, 1):
            meeting_id = meeting['id']
            meeting_topic = meeting.get('topic', 'Unknown')
            if idx % 10 == 0 or idx == len(meetings):
                print(f"   Processing meeting {idx}/{len(meetings)}...")
            
            participants = self._get_meeting_participants(meeting_id)
            
            for participant in participants:
                ip_address = participant.get('ip_address')
                if not ip_address:
                    continue
                
                # Get user name and email with proper fallbacks
                user_name = participant.get('user_name', participant.get('name', 'Unknown'))
                user_email = participant.get('user_email', participant.get('email', ''))
                
                # If no email, check if user_name is an email
                if not user_email and '@' in user_name:
                    user_email = user_name
                elif not user_email:
                    user_email = 'Unknown'
                
                # For display name, use the part before @ if it's an email, otherwise use as-is
                display_name = user_name.split('@')[0] if '@' in user_name else user_name
                
                log_entry = {
                    'user': display_name,
                    'email': user_email,
                    'user_id': participant.get('user_id', participant.get('id', 'Unknown')),
                    'ip': ip_address,
                    'timestamp': participant.get('join_time', datetime.now(timezone.utc).isoformat()),
                    'action': 'meeting_participant',
                    'meeting_topic': meeting_topic,
                    'meeting_id': meeting_id,
                    'duration': participant.get('duration', 0),
                    'location': participant.get('location', 'Unknown')
                }
                logs.append(log_entry)
            
            # Rate limiting
            time.sleep(0.3)
        
        print(f"   ✓ Retrieved {len(logs)} Zoom participant entries")
        return logs
    
    def _get_past_meetings(self, start_date: datetime, end_date: datetime) -> List[Dict]:
        """Get list of past meetings using Dashboard API."""
        meetings = []
        next_page_token = None
        
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        while True:
            params = {
                'type': 'past',  # Important: Must specify 'past' to get completed meetings
                'from': start_date.strftime('%Y-%m-%d'),
                'to': end_date.strftime('%Y-%m-%d'),
                'page_size': 30
            }
            
            if next_page_token:
                params['next_page_token'] = next_page_token
            
            try:
                response = requests.get(
                    f"{self.BASE_URL}/metrics/meetings",
                    headers=headers,
                    params=params,
                    timeout=30
                )
                
                if response.status_code == 403:
                    raise Exception(
                        "Access denied to Dashboard API. This requires:\n"
                        "  1. Business or Business+ Zoom plan (not Pro)\n"
                        "  2. dashboard_meetings:read:admin scope\n"
                        "  3. Dashboard feature enabled in your account"
                    )
                
                response.raise_for_status()
                data = response.json()
                
                meetings.extend(data.get('meetings', []))
                
                next_page_token = data.get('next_page_token')
                if not next_page_token:
                    break
                
                # Rate limiting
                time.sleep(0.3)
                    
            except requests.exceptions.RequestException as e:
                raise Exception(f"Failed to fetch Zoom meetings: {str(e)}")
        
        return meetings
    
    def _get_meeting_participants(self, meeting_id: str) -> List[Dict]:
        """Get participants for a specific meeting with IP addresses."""
        participants = []
        next_page_token = None
        
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        while True:
            params = {
                'page_size': 30,
                'include_fields': 'registrant_id',  # This ensures we get all participant details including IPs
                'type': 'past'
            }
            
            if next_page_token:
                params['next_page_token'] = next_page_token
            
            try:
                # Use numeric meeting ID directly (no encoding needed)
                response = requests.get(
                    f"{self.BASE_URL}/metrics/meetings/{meeting_id}/participants",
                    headers=headers,
                    params=params,
                    timeout=30
                )
                
                # Meeting might not have participants or might be too old
                if response.status_code == 404:
                    break
                
                response.raise_for_status()
                data = response.json()
                
                participants.extend(data.get('participants', []))
                
                next_page_token = data.get('next_page_token')
                if not next_page_token:
                    break
                    
            except requests.exceptions.RequestException:
                # Some meetings may not have accessible participant data
                break
        
        return participants
    
    def test_connection(self) -> bool:
        """Test if the credentials are valid and have Dashboard API access."""
        try:
            self._ensure_authenticated()
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }
            
            # Test Dashboard API access
            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=1)
            
            response = requests.get(
                f"{self.BASE_URL}/metrics/meetings",
                headers=headers,
                params={
                    'type': 'past',
                    'from': start_date.strftime('%Y-%m-%d'),
                    'to': end_date.strftime('%Y-%m-%d'),
                    'page_size': 1
                },
                timeout=10
            )
            
            if response.status_code == 403:
                print("   ⚠️  Dashboard API access denied - requires Business/Business+ plan")
                return False
            
            response.raise_for_status()
            return True
        except Exception:
            return False
