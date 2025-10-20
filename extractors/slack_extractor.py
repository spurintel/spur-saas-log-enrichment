"""Slack IP address and user extractor."""

import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List
import requests


class SlackExtractor:
    """Extract IP addresses and user information from Slack access logs."""
    
    BASE_URL = "https://slack.com/api"
    
    def __init__(self, api_token: str):
        """
        Initialize Slack extractor.
        
        Args:
            api_token: Slack API token with admin scope (works with any paid Slack plan)
                      For Enterprise Grid, can use admin.teams:read, users:read, users:read.email instead
        """
        self.api_token = api_token
        self.headers = {
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json'
        }
        self.user_cache = {}
    
    def _get_user_info(self, user_id: str) -> Dict:
        """Get user information from cache or API."""
        if user_id in self.user_cache:
            return self.user_cache[user_id]
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/users.info",
                headers=self.headers,
                params={'user': user_id},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            
            if data.get('ok') and data.get('user'):
                user = data['user']
                user_info = {
                    'name': user.get('name', 'Unknown'),
                    'real_name': user.get('real_name', 'Unknown'),
                    'email': user.get('profile', {}).get('email', 'Unknown')
                }
                self.user_cache[user_id] = user_info
                return user_info
        except Exception:
            pass
        
        return {'name': 'Unknown', 'real_name': 'Unknown', 'email': 'Unknown'}
    
    def extract_ip_logs(self, days: int = 30) -> List[Dict]:
        """
        Extract IP address logs from Slack using team.accessLogs API.
        
        Args:
            days: Number of days to look back (max 7 days for most plans)
            
        Returns:
            List of dicts with user, email, ip, timestamp, and action
        """
        logs = []
        
        # Note: team.accessLogs only provides last 7 days for Standard/Plus
        # Enterprise Grid can go back further
        if days > 7:
            print(f"   ⚠️  Note: Slack access logs are limited to 7 days on Standard/Plus plans")
            print(f"   Requesting {days} days, but may receive less depending on your plan")
        
        # Calculate time range (team.accessLogs uses 'before' parameter)
        # We'll fetch in pages going backwards from now
        before = int(datetime.now(timezone.utc).timestamp())
        oldest = int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp())
        
        page = 0
        total_entries = 0
        
        while True:
            page += 1
            params = {
                'before': before,
                'count': 1000  # Max per request
            }
            
            try:
                response = requests.get(
                    f"{self.BASE_URL}/team.accessLogs",
                    headers=self.headers,
                    params=params,
                    timeout=30
                )
                response.raise_for_status()
                data = response.json()
                
                if not data.get('ok'):
                    error_msg = data.get('error', 'Unknown error')
                    if error_msg == 'missing_scope':
                        raise Exception(
                            "Missing required scope. Please ensure your token has 'admin' scope "
                            "(or 'admin.teams:read' on Enterprise Grid) and was created by a workspace admin."
                        )
                    elif error_msg == 'paid_only':
                        raise Exception(
                            "team.accessLogs requires a paid Slack plan (Standard, Plus, or Enterprise Grid). "
                            "Free workspaces do not have access to this API."
                        )
                    raise Exception(f"Slack API error: {error_msg}")
                
                logins = data.get('logins', [])
                
                if not logins:
                    break
                
                print(f"   Fetching page {page}...")
                total_entries += len(logins)
                
                # Track the oldest timestamp in this batch for pagination
                oldest_in_batch = None
                
                # Process entries
                for login in logins:
                    # Check if this entry is within our time range
                    date_first = login.get('date_first', 0)
                    
                    # Track oldest timestamp for next page
                    if oldest_in_batch is None or date_first < oldest_in_batch:
                        oldest_in_batch = date_first
                    
                    if date_first < oldest:
                        # We've gone past our time range
                        continue
                    
                    user_id = login.get('user_id')
                    ip_address = login.get('ip')
                    
                    if not ip_address or not user_id:
                        continue
                    
                    # Get user info (cached to minimize API calls)
                    user_info = self._get_user_info(user_id)
                    
                    log_entry = {
                        'user': user_info['name'],
                        'email': user_info['email'],
                        'user_id': user_id,
                        'ip': ip_address,
                        'timestamp': datetime.fromtimestamp(date_first).isoformat(),
                        'action': 'user_login',
                        'user_agent': login.get('user_agent', 'Unknown'),
                        'count': login.get('count', 1)  # Number of times this IP was used
                    }
                    logs.append(log_entry)
                
                # Update 'before' to the oldest timestamp from this batch
                # This is used for the next page request
                if oldest_in_batch is None or oldest_in_batch == before:
                    # No progress made, stop to avoid infinite loop
                    break
                
                before = oldest_in_batch
                
                # If we've hit our time limit, stop
                if before <= oldest:
                    break
                
                # Check if we should continue based on paging info
                paging = data.get('paging', {})
                current_page = paging.get('page', 1)
                total_pages = paging.get('pages', 1)
                
                if current_page >= total_pages:
                    break
                
                # Rate limiting: be nice to the API
                time.sleep(0.5)
                
            except requests.exceptions.RequestException as e:
                raise Exception(f"Failed to fetch Slack access logs: {str(e)}")
        
        print(f"   ✓ Retrieved {total_entries} Slack log entries")
        return logs
    
    def test_connection(self) -> bool:
        """Test if the API token is valid and has necessary permissions."""
        try:
            # Test auth.test first to verify token is valid
            response = requests.get(
                f"{self.BASE_URL}/auth.test",
                headers=self.headers,
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            
            if not data.get('ok'):
                return False
            
            # Now test team.accessLogs with minimal request
            response = requests.get(
                f"{self.BASE_URL}/team.accessLogs",
                headers=self.headers,
                params={'count': 1},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            
            return data.get('ok', False)
        except Exception:
            return False

