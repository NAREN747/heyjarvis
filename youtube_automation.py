"""
JARVIS YouTube Automation — YouTube Data API v3 integration.
Handles channel access, video upload, metadata editing, and thumbnail management.
"""
from __future__ import annotations

import asyncio
import os
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

import httpx
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaFileUpload

# Scopes required for YouTube Data API v3
SCOPES = [
    "https://www.googleapis.com/auth/youtube.upload",
    "https://www.googleapis.com/auth/youtube",
    "https://www.googleapis.com/auth/youtube.force-ssl",
]


@dataclass
class VideoMetadata:
    """Video metadata for upload/update."""
    title: str
    description: str = ""
    tags: list[str] = None
    category_id: str = "22"  # People & Blogs
    privacy_status: str = "private"  # private, unlisted, public
    publish_at: Optional[datetime] = None
    thumbnail_path: Optional[str] = None
    playlist_id: Optional[str] = None
    made_for_kids: bool = False
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []


@dataclass
class VideoUploadResult:
    """Result of video upload operation."""
    video_id: str
    url: str
    status: str
    metadata: VideoMetadata


class YouTubeAutomation:
    """
    YouTube automation using YouTube Data API v3.
    Handles authentication, upload, metadata editing, and thumbnail management.
    """
    
    def __init__(
        self,
        client_secrets_path: str,
        token_path: str,
        broadcast: Callable[[dict], Any] | None = None,
    ):
        self.client_secrets_path = Path(client_secrets_path)
        self.token_path = Path(token_path)
        self.broadcast = broadcast or (lambda msg: None)
        self._service = None
        self._credentials = None
    
    async def authenticate(self) -> bool:
        """Authenticate with YouTube API using OAuth 2.0."""
        try:
            # Load existing token
            if self.token_path.exists():
                self._credentials = Credentials.from_authorized_user_file(
                    str(self.token_path), SCOPES
                )
            
            # Refresh or get new credentials
            if not self._credentials or not self._credentials.valid:
                if self._credentials and self._credentials.expired and self._credentials.refresh_token:
                    self._credentials.refresh(Request())
                else:
                    if not self.client_secrets_path.exists():
                        raise FileNotFoundError(
                            f"Client secrets not found at {self.client_secrets_path}. "
                            "Download from Google Cloud Console."
                        )
                    flow = InstalledAppFlow.from_client_secrets_file(
                        str(self.client_secrets_path), SCOPES
                    )
                    self._credentials = flow.run_local_server(port=0)
                
                # Save credentials
                self.token_path.write_text(self._credentials.to_json())
            
            # Build service
            self._service = build("youtube", "v3", credentials=self._credentials)
            
            await self.broadcast({
                "type": "system",
                "message": "YouTube API authenticated successfully"
            })
            return True
            
        except Exception as e:
            await self.broadcast({
                "type": "error",
                "message": f"YouTube auth failed: {e}"
            })
            return False
    
    @property
    def is_authenticated(self) -> bool:
        return self._service is not None and self._credentials is not None
    
    def _ensure_auth(self):
        if not self.is_authenticated:
            raise RuntimeError("Not authenticated. Call authenticate() first.")
    
    # --- Channel Info ---
    
    async def get_my_channel(self) -> dict:
        """Get authenticated user's channel info."""
        self._ensure_auth()
        try:
            response = self._service.channels().list(
                part="snippet,statistics,contentDetails",
                mine=True
            ).execute()
            
            if response.get("items"):
                channel = response["items"][0]
                return {
                    "channel_id": channel["id"],
                    "title": channel["snippet"]["title"],
                    "description": channel["snippet"]["description"],
                    "custom_url": channel["snippet"].get("customUrl"),
                    "subscriber_count": channel["statistics"].get("subscriberCount"),
                    "view_count": channel["statistics"].get("viewCount"),
                    "video_count": channel["statistics"].get("videoCount"),
                    "uploads_playlist_id": channel["contentDetails"]["relatedPlaylists"]["uploads"],
                }
            return {}
        except HttpError as e:
            raise RuntimeError(f"Failed to get channel info: {e}")
    
    async def get_channel_by_id(self, channel_id: str) -> dict:
        """Get channel info by ID."""
        self._ensure_auth()
        try:
            response = self._service.channels().list(
                part="snippet,statistics,contentDetails",
                id=channel_id
            ).execute()
            
            if response.get("items"):
                return self._parse_channel(response["items"][0])
            return {}
        except HttpError as e:
            raise RuntimeError(f"Failed to get channel: {e}")
    
    def _parse_channel(self, channel: dict) -> dict:
        return {
            "channel_id": channel["id"],
            "title": channel["snippet"]["title"],
            "description": channel["snippet"]["description"],
            "custom_url": channel["snippet"].get("customUrl"),
            "subscriber_count": channel["statistics"].get("subscriberCount"),
            "view_count": channel["statistics"].get("viewCount"),
            "video_count": channel["statistics"].get("videoCount"),
            "uploads_playlist_id": channel["contentDetails"]["relatedPlaylists"]["uploads"],
        }
    
    # --- Video Operations ---
    
    async def upload_video(
        self,
        file_path: str,
        metadata: VideoMetadata,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> VideoUploadResult:
        """Upload a video to YouTube."""
        self._ensure_auth()
        
        if not Path(file_path).exists():
            raise FileNotFoundError(f"Video file not found: {file_path}")
        
        # Build request body
        body = {
            "snippet": {
                "title": metadata.title,
                "description": metadata.description,
                "tags": metadata.tags,
                "categoryId": metadata.category_id,
            },
            "status": {
                "privacyStatus": metadata.privacy_status,
                "madeForKids": metadata.made_for_kids,
            },
        }
        
        if metadata.publish_at:
            body["status"]["publishAt"] = metadata.publish_at.isoformat() + "Z"
            body["status"]["privacyStatus"] = "private"  # Required for scheduled
        
        # Prepare media upload
        media = MediaFileUpload(
            file_path,
            chunksize=1024 * 1024,  # 1MB chunks
            resumable=True,
            mimetype="video/*",
        )
        
        try:
            request = self._service.videos().insert(
                part="snippet,status",
                body=body,
                media_body=media,
            )
            
            # Upload with progress tracking
            response = None
            while response is None:
                status, response = request.next_chunk()
                if status and progress_callback:
                    progress_callback(status.resumable_progress, status.total_size)
            
            video_id = response["id"]
            video_url = f"https://www.youtube.com/watch?v={video_id}"
            
            # Set thumbnail if provided
            if metadata.thumbnail_path:
                await self.set_thumbnail(video_id, metadata.thumbnail_path)
            
            # Add to playlist if specified
            if metadata.playlist_id:
                await self.add_to_playlist(metadata.playlist_id, video_id)
            
            return VideoUploadResult(
                video_id=video_id,
                url=video_url,
                status="uploaded",
                metadata=metadata,
            )
            
        except HttpError as e:
            raise RuntimeError(f"Upload failed: {e}")
    
    async def update_video(
        self,
        video_id: str,
        metadata: VideoMetadata,
    ) -> dict:
        """Update video metadata."""
        self._ensure_auth()
        
        body = {
            "id": video_id,
            "snippet": {
                "title": metadata.title,
                "description": metadata.description,
                "tags": metadata.tags,
                "categoryId": metadata.category_id,
            },
        }
        
        try:
            response = self._service.videos().update(
                part="snippet",
                body=body,
            ).execute()
            return response
        except HttpError as e:
            raise RuntimeError(f"Update failed: {e}")
    
    async def delete_video(self, video_id: str) -> bool:
        """Delete a video."""
        self._ensure_auth()
        try:
            self._service.videos().delete(id=video_id).execute()
            return True
        except HttpError as e:
            raise RuntimeError(f"Delete failed: {e}")
    
    async def set_thumbnail(self, video_id: str, thumbnail_path: str) -> bool:
        """Set video thumbnail."""
        self._ensure_auth()
        
        if not Path(thumbnail_path).exists():
            raise FileNotFoundError(f"Thumbnail not found: {thumbnail_path}")
        
        try:
            media = MediaFileUpload(thumbnail_path, resumable=True)
            self._service.thumbnails().set(
                videoId=video_id,
                media_body=media,
            ).execute()
            return True
        except HttpError as e:
            raise RuntimeError(f"Thumbnail upload failed: {e}")
    
    async def add_to_playlist(self, playlist_id: str, video_id: str) -> dict:
        """Add video to playlist."""
        self._ensure_auth()
        try:
            response = self._service.playlistItems().insert(
                part="snippet",
                body={
                    "snippet": {
                        "playlistId": playlist_id,
                        "resourceId": {
                            "kind": "youtube#video",
                            "videoId": video_id,
                        },
                    },
                },
            ).execute()
            return response
        except HttpError as e:
            raise RuntimeError(f"Add to playlist failed: {e}")
    
    async def get_video_stats(self, video_id: str) -> dict:
        """Get video statistics."""
        self._ensure_auth()
        try:
            response = self._service.videos().list(
                part="statistics,snippet,contentDetails,status",
                id=video_id
            ).execute()
            
            if response.get("items"):
                return response["items"][0]
            return {}
        except HttpError as e:
            raise RuntimeError(f"Failed to get video stats: {e}")
    
    async def list_my_videos(
        self,
        max_results: int = 50,
        order: str = "date",  # date, rating, relevance, title, videoCount, viewCount
    ) -> list[dict]:
        """List own uploaded videos."""
        self._ensure_auth()
        try:
            # Get uploads playlist
            channel = await self.get_my_channel()
            uploads_playlist = channel.get("uploads_playlist_id")
            
            if not uploads_playlist:
                return []
            
            videos = []
            next_page_token = None
            
            while len(videos) < max_results:
                response = self._service.playlistItems().list(
                    part="snippet,contentDetails",
                    playlistId=uploads_playlist,
                    maxResults=min(50, max_results - len(videos)),
                    pageToken=next_page_token,
                ).execute()
                
                for item in response.get("items", []):
                    snippet = item["snippet"]
                    videos.append({
                        "video_id": item["contentDetails"]["videoId"],
                        "title": snippet["title"],
                        "description": snippet["description"],
                        "published_at": snippet["publishedAt"],
                        "thumbnails": snippet["thumbnails"],
                    })
                
                next_page_token = response.get("nextPageToken")
                if not next_page_token:
                    break
            
            return videos
        except HttpError as e:
            raise RuntimeError(f"Failed to list videos: {e}")

    # --- Playlist Operations ---
    
    async def create_playlist(
        self,
        title: str,
        description: str = "",
        privacy_status: str = "private",
    ) -> dict:
        """Create a new playlist."""
        self._ensure_auth()
        try:
            response = self._service.playlists().insert(
                part="snippet,status",
                body={
                    "snippet": {
                        "title": title,
                        "description": description,
                    },
                    "status": {
                        "privacyStatus": privacy_status,
                    },
                },
            ).execute()
            return response
        except HttpError as e:
            raise RuntimeError(f"Create playlist failed: {e}")
    
    async def list_my_playlists(self, max_results: int = 50) -> list[dict]:
        """List own playlists."""
        self._ensure_auth()
        try:
            playlists = []
            next_page_token = None
            
            while len(playlists) < max_results:
                response = self._service.playlists().list(
                    part="snippet,contentDetails",
                    mine=True,
                    maxResults=min(50, max_results - len(playlists)),
                    pageToken=next_page_token,
                ).execute()
                
                for item in response.get("items", []):
                    playlists.append({
                        "playlist_id": item["id"],
                        "title": item["snippet"]["title"],
                        "description": item["snippet"]["description"],
                        "item_count": item["contentDetails"]["itemCount"],
                        "privacy_status": item["status"]["privacyStatus"],
                    })
                
                next_page_token = response.get("nextPageToken")
                if not next_page_token:
                    break
            
            return playlists
        except HttpError as e:
            raise RuntimeError(f"List playlists failed: {e}")

    # --- Analytics ---
    
    async def get_channel_analytics(
        self,
        start_date: str,
        end_date: str,
        metrics: list[str] = None,
        dimensions: list[str] = None,
    ) -> dict:
        """
        Get channel analytics.
        Note: Requires YouTube Analytics API (separate API enable).
        """
        # Placeholder - requires YouTube Analytics API
        return {"error": "YouTube Analytics API not configured"}


# --- OAuth Helpers ---

async def get_youtube_auth_url(client_secrets_path: str, redirect_uri: str = "http://localhost:8080/callback") -> str:
    """Generate YouTube OAuth authorization URL."""
    flow = InstalledAppFlow.from_client_secrets_file(
        client_secrets_path,
        SCOPES,
        redirect_uri=redirect_uri,
    )
    auth_url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    return auth_url


async def exchange_code_for_tokens(
    client_secrets_path: str,
    code: str,
    redirect_uri: str = "http://localhost:8080/callback",
) -> Credentials:
    """Exchange authorization code for tokens."""
    flow = InstalledAppFlow.from_client_secrets_file(
        client_secrets_path,
        SCOPES,
        redirect_uri=redirect_uri,
    )
    flow.fetch_token(code=code)
    return flow.credentials