#!/usr/bin/env python3
"""
Zepto Automation - Terminal Version with Scheduler
Runs Gmail to Drive and Drive to Sheet workflows with logging
"""

import os
import json
import base64
import tempfile
import time
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import io
import schedule

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseUpload
from llama_cloud_services import LlamaExtract

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('zepto_automation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SheetLogHandler(logging.Handler):
    """Custom handler to collect detailed logs for Google Sheet"""
    def __init__(self, automation):
        super().__init__()
        self.automation = automation

    def emit(self, record):
        try:
            timestamp = datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S')
            workflow = self.automation.current_workflow or "General"
            level = record.levelname
            message = record.getMessage()
            self.automation.logs.append([timestamp, workflow, level, message])
        except Exception:
            pass

class ZeptoAutomationTerminal:
    def __init__(self):
        self.gmail_service = None
        self.drive_service = None
        self.sheets_service = None
        
        # API scopes
        self.gmail_scopes = ['https://www.googleapis.com/auth/gmail.readonly']
        self.drive_scopes = ['https://www.googleapis.com/auth/drive.file']
        self.sheets_scopes = ['https://www.googleapis.com/auth/spreadsheets']
        
        # Hardcoded configuration (similar to zeptogrn.py defaults)
        self.config = {
            'gmail_workflow': {
                'sender': "procurement@zeptonow.com",
                'search_term': "grn",
                'days_back': 2,
                'max_results': 1000,
                'attachment_filter': "",
                'gdrive_folder_id': "1UztLKOp-job-BeKqcLV16dPLBlF1cV19"
            },
            'pdf_workflow': {
                'drive_folder_id': "18LRA2eMtHVPXQ2lQa5tuaYk9CAYNVJsW",
                'llama_api_key': "llx-phVffvtXpilg0AkQjsVllzITv9eXIZ3dPvwx8rI1EeEGsuDZ",
                'llama_agent': "Zepto Agent",
                'spreadsheet_id': "1YgLZfg7g07_koytHmEXEdy_BxU5sje3T1Ugnav0MIGI",
                'sheet_range': "zeptogrn",
                'days_back': 2,
                'max_files': 500,
                'skip_existing': True
            },
            'logging': {
                'spreadsheet_id': "1YgLZfg7g07_koytHmEXEdy_BxU5sje3T1Ugnav0MIGI",
                'log_sheet': "workflow_logs",
                'detailed_log_sheet': "detailed_logs"
            }
        }
        self.logs = []
        self.current_workflow = None
        logger.addHandler(SheetLogHandler(self))
        logger.info("Configuration loaded successfully")
    
    def authenticate(self):
        """Authenticate using environment variables instead of local files"""
        try:
            logger.info("Starting authentication process (Render version)...")
            creds = None
    
            # Load credentials from environment
            if "GOOGLE_TOKEN_JSON" in os.environ:
                creds = Credentials.from_authorized_user_info(
                    json.loads(os.environ["GOOGLE_TOKEN_JSON"]),
                    scopes=self.gmail_scopes + self.drive_scopes + self.sheets_scopes
                )
    
            # If expired or missing, refresh or recreate
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    logger.info("Refreshing expired credentials...")
                    creds.refresh(Request())
                elif "GOOGLE_CREDENTIALS_JSON" in os.environ:
                    logger.info("Starting new OAuth flow from credentials...")
                    flow = InstalledAppFlow.from_client_config(
                        json.loads(os.environ["GOOGLE_CREDENTIALS_JSON"]),
                        self.gmail_scopes + self.drive_scopes + self.sheets_scopes
                    )
                    creds = flow.run_local_server(port=0)
    
                # Save updated token in memory (optional)
                os.environ["GOOGLE_TOKEN_JSON"] = creds.to_json()
    
            # Build API clients
            self.gmail_service = build("gmail", "v1", credentials=creds)
            self.drive_service = build("drive", "v3", credentials=creds)
            self.sheets_service = build("sheets", "v4", credentials=creds)
    
            logger.info("Authentication successful (Render env mode)")
            return True
    
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            return False
    
    def search_emails(self, sender: str = "", search_term: str = "", 
                     days_back: int = 7, max_results: int = 50) -> List[Dict]:
        """Search for emails with attachments"""
        try:
            # Build search query
            query_parts = ["has:attachment"]
            
            if sender:
                query_parts.append(f'from:"{sender}"')
            
            if search_term:
                if "," in search_term:
                    keywords = [k.strip() for k in search_term.split(",")]
                    keyword_query = " OR ".join([f'"{k}"' for k in keywords if k])
                    if keyword_query:
                        query_parts.append(f"({keyword_query})")
                else:
                    query_parts.append(f'"{search_term}"')
            
            # Add date filter
            start_date = datetime.now() - timedelta(days=days_back)
            query_parts.append(f"after:{start_date.strftime('%Y/%m/%d')}")
            
            query = " ".join(query_parts)
            logger.info(f"Searching Gmail with query: {query}")
            
            # Execute search
            result = self.gmail_service.users().messages().list(
                userId='me', q=query, maxResults=max_results
            ).execute()
            
            messages = result.get('messages', [])
            logger.info(f"Gmail search returned {len(messages)} messages")
            
            return messages
            
        except Exception as e:
            logger.error(f"Email search failed: {str(e)}")
            return []
    
    def process_gmail_workflow(self):
        """Process Gmail attachment download workflow"""
        workflow_start = datetime.now()
        workflow_name = "Gmail to Drive"
        
        try:
            logger.info("=" * 60)
            logger.info(f"Starting {workflow_name} workflow...")
            logger.info("=" * 60)
            
            config = self.config['gmail_workflow']
            
            # Search for emails
            emails = self.search_emails(
                sender=config['sender'],
                search_term=config['search_term'],
                days_back=config['days_back'],
                max_results=config['max_results']
            )
            
            if not emails:
                logger.warning("No emails found matching criteria")
                drive_count = self.count_unique_files_in_drive(self.config['gmail_workflow']['gdrive_folder_id'])
                sheet_count = self.count_unique_files_in_sheet(self.config['pdf_workflow']['spreadsheet_id'], self.config['pdf_workflow']['sheet_range'])
                self.log_workflow(workflow_name, workflow_start, 0, 0, "Success - No emails found", drive_count, sheet_count)
                return {'success': True, 'processed': 0}
            
            logger.info(f"Found {len(emails)} emails matching criteria")
            
            # Create base folder in Drive
            base_folder_name = "Gmail_Attachments"
            base_folder_id = self._create_drive_folder(base_folder_name, config.get('gdrive_folder_id'))
            
            if not base_folder_id:
                logger.error("Failed to create base folder in Google Drive")
                drive_count = 0
                sheet_count = 0
                self.log_workflow(workflow_name, workflow_start, 0, 0, "Failed - Could not create base folder", drive_count, sheet_count)
                return {'success': False, 'processed': 0}
            
            processed_count = 0
            total_attachments = 0
            
            for i, email in enumerate(emails):
                try:
                    logger.info(f"Processing email {i+1}/{len(emails)}")
                    
                    # Get email details first
                    email_details = self._get_email_details(email['id'])
                    subject = email_details.get('subject', 'No Subject')[:50]
                    sender = email_details.get('sender', 'Unknown')
                    
                    logger.info(f"Email: {subject} from {sender}")
                    
                    # Get full message with payload
                    message = self.gmail_service.users().messages().get(
                        userId='me', id=email['id'], format='full'
                    ).execute()
                    
                    if not message or not message.get('payload'):
                        logger.warning(f"No payload found for email: {subject}")
                        continue
                    
                    # Extract attachments
                    attachment_count = self._extract_attachments_from_email(
                        email['id'], message['payload'], sender, config, base_folder_id
                    )
                    
                    total_attachments += attachment_count
                    if attachment_count > 0:
                        processed_count += 1
                        logger.info(f"Found {attachment_count} attachments in: {subject}")
                    
                except Exception as e:
                    logger.error(f"Failed to process email {email.get('id', 'unknown')}: {str(e)}")
            
            # Count unique files in Drive and Sheet after workflow
            drive_count = self.count_unique_files_in_drive(self.config['gmail_workflow']['gdrive_folder_id'])
            sheet_count = self.count_unique_files_in_sheet(self.config['pdf_workflow']['spreadsheet_id'], self.config['pdf_workflow']['sheet_range'])
            
            logger.info("=" * 60)
            logger.info(f"{workflow_name} completed! Processed {total_attachments} attachments from {processed_count} emails")
            logger.info(f"Unique files in Drive: {drive_count}")
            logger.info(f"Unique entries in Sheet: {sheet_count}")
            logger.info("=" * 60)
            
            # Log to sheet
            self.log_workflow(
                workflow_name, 
                workflow_start, 
                len(emails), 
                total_attachments, 
                "Success", 
                drive_count,
                sheet_count
            )
            
            return {'success': True, 'processed': total_attachments}
            
        except Exception as e:
            logger.error(f"Gmail workflow failed: {str(e)}")
            drive_count = 0
            sheet_count = 0
            self.log_workflow(workflow_name, workflow_start, 0, 0, f"Failed - {str(e)}", drive_count, sheet_count)
            return {'success': False, 'processed': 0}
    
    def _get_email_details(self, message_id: str) -> Dict:
        """Get email details including sender and subject"""
        try:
            message = self.gmail_service.users().messages().get(
                userId='me', id=message_id, format='metadata'
            ).execute()
            
            headers = message['payload'].get('headers', [])
            
            details = {
                'id': message_id,
                'sender': next((h['value'] for h in headers if h['name'] == "From"), "Unknown"),
                'subject': next((h['value'] for h in headers if h['name'] == "Subject"), "(No Subject)"),
                'date': next((h['value'] for h in headers if h['name'] == "Date"), "")
            }
            
            return details
            
        except Exception as e:
            logger.error(f"Failed to get email details for {message_id}: {str(e)}")
            return {'id': message_id, 'sender': 'Unknown', 'subject': 'Unknown', 'date': ''}

    def _extract_attachments_from_email(self, message_id: str, payload: Dict, sender: str, config: dict, base_folder_id: str) -> int:
        """Extract attachments from email with proper folder structure"""
        processed_count = 0
        
        if "parts" in payload:
            for part in payload["parts"]:
                processed_count += self._extract_attachments_from_email(
                    message_id, part, sender, config, base_folder_id
                )
        elif payload.get("filename") and "attachmentId" in payload.get("body", {}):
            filename = payload.get("filename", "")
            
            # Optional attachment filter
            if config.get('attachment_filter'):
                if filename.lower() != config['attachment_filter'].lower():
                    return 0
            
            try:
                # Get attachment data
                attachment_id = payload["body"].get("attachmentId")
                att = self.gmail_service.users().messages().attachments().get(
                    userId='me', messageId=message_id, id=attachment_id
                ).execute()
                
                file_data = base64.urlsafe_b64decode(att["data"].encode("UTF-8"))
                
                # Create the exact folder structure: Gmail_Attachments -> procurement@zeptonow.com -> grn -> PDFs
                sender_folder_id = self._create_drive_folder("procurement@zeptonow.com", base_folder_id)
                grn_folder_id = self._create_drive_folder("grn", sender_folder_id)
                pdfs_folder_id = self._create_drive_folder("PDFs", grn_folder_id)
                
                # Upload file with message ID prefix
                prefixed_filename = f"{message_id}_{filename}"
                
                # Check if file already exists
                query = f"name='{prefixed_filename}' and '{pdfs_folder_id}' in parents and trashed=false"
                existing = self.drive_service.files().list(q=query, fields='files(id)').execute()
                files = existing.get('files', [])
                
                if files:
                    logger.info(f"Skipping duplicate file: {prefixed_filename}")
                    return 0
                
                file_metadata = {
                    'name': prefixed_filename,
                    'parents': [pdfs_folder_id]
                }
                
                media = MediaIoBaseUpload(io.BytesIO(file_data), mimetype='application/octet-stream')
                
                file = self.drive_service.files().create(
                    body=file_metadata,
                    media_body=media,
                    fields='id'
                ).execute()
                
                logger.info(f"Uploaded {prefixed_filename} to Drive")
                processed_count += 1
                
            except Exception as e:
                logger.error(f"Failed to process attachment {filename}: {str(e)}")
        
        return processed_count

    def _create_drive_folder(self, folder_name: str, parent_folder_id: Optional[str] = None) -> str:
        """Create a folder in Google Drive or return existing one"""
        try:
            # First check if folder already exists
            query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
            if parent_folder_id:
                query += f" and '{parent_folder_id}' in parents"
            
            existing = self.drive_service.files().list(q=query, fields='files(id, name)').execute()
            files = existing.get('files', [])
            
            if files:
                return files[0]['id']
            
            # Create new folder
            folder_metadata = {
                'name': folder_name,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            
            if parent_folder_id:
                folder_metadata['parents'] = [parent_folder_id]
            
            folder = self.drive_service.files().create(
                body=folder_metadata,
                fields='id'
            ).execute()
            
            return folder.get('id')
            
        except Exception as e:
            logger.error(f"Failed to create folder {folder_name}: {str(e)}")
            return ""
    
    def _get_all_drive_pdf_files(self, folder_id: str) -> List[Dict]:
        """Recursively get all PDF files in Drive folder"""
        try:
            files = []
            # Direct PDFs
            query = f"'{folder_id}' in parents and mimeType='application/pdf' and trashed=false"
            page_token = None
            while True:
                results = self.drive_service.files().list(
                    q=query,
                    fields="nextPageToken, files(id, name)",
                    pageToken=page_token
                ).execute()
                files.extend(results.get('files', []))
                page_token = results.get('nextPageToken')
                if not page_token:
                    break
            
            # Subfolders
            subfolders_query = f"'{folder_id}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false"
            subfolders_result = self.drive_service.files().list(
                q=subfolders_query,
                fields="files(id)"
            ).execute()
            subfolders = subfolders_result.get('files', [])
            for subfolder in subfolders:
                files.extend(self._get_all_drive_pdf_files(subfolder['id']))
            
            return files
            
        except Exception as e:
            logger.error(f"Failed to get all PDF files: {str(e)}")
            return []
    
    def get_all_drive_pdf_names(self, folder_id: str) -> set:
        """Get set of all PDF file names in Drive folder recursively"""
        files = self._get_all_drive_pdf_files(folder_id)
        return {f['name'] for f in files}
    
    def count_unique_files_in_drive(self, folder_id: str) -> int:
        """Count unique files in Drive folder (recursively)"""
        return len(self.get_all_drive_pdf_names(folder_id))
    
    def process_pdf_workflow(self):
        """Process PDF workflow with LlamaParse"""
        workflow_start = datetime.now()
        workflow_name = "Drive to Sheet"
        
        try:
            logger.info("=" * 60)
            logger.info(f"Starting {workflow_name} workflow...")
            logger.info("=" * 60)
            
            config = self.config['pdf_workflow']
            
            # List PDFs
            pdf_files = self._list_drive_files(config['drive_folder_id'], config['days_back'])
            
            if config.get('skip_existing', True):
                existing_names = self.get_existing_source_files(
                    config['spreadsheet_id'], 
                    config['sheet_range']
                )
                pdf_files = [f for f in pdf_files if f['name'] not in existing_names]
                logger.info(f"After filtering existing, {len(pdf_files)} PDFs to process")
            
            if config.get('max_files') is not None:
                pdf_files = pdf_files[:config['max_files']]
                logger.info(f"Limited to {config['max_files']} PDFs")
            
            if not pdf_files:
                logger.warning("No PDF files found to process")
                drive_count = self.count_unique_files_in_drive(config['drive_folder_id'])
                sheet_count = self.count_unique_files_in_sheet(config['spreadsheet_id'], config['sheet_range'])
                self.log_workflow(workflow_name, workflow_start, 0, 0, "Success - No PDFs to process", drive_count, sheet_count)
                return {'success': True, 'processed': 0}
            
            logger.info(f"Found {len(pdf_files)} PDFs to process")
            
            # Setup LlamaParse
            os.environ["LLAMA_CLOUD_API_KEY"] = config['llama_api_key']
            extractor = LlamaExtract()
            agent = extractor.get_agent(name=config['llama_agent'])
            
            if agent is None:
                logger.error(f"Could not find LlamaParse agent '{config['llama_agent']}'")
                drive_count = 0
                sheet_count = 0
                self.log_workflow(workflow_name, workflow_start, len(pdf_files), 0, "Failed - Agent not found", drive_count, sheet_count)
                return {'success': False, 'processed': 0}
            
            processed_count = 0
            rows_added = 0
            
            for i, file in enumerate(pdf_files):
                try:
                    logger.info(f"Processing PDF {i+1}/{len(pdf_files)}: {file['name']}")
                    
                    # Download PDF
                    pdf_data = self._download_from_drive(file['id'])
                    if not pdf_data:
                        logger.warning(f"Failed to download {file['name']}")
                        continue
                    
                    with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as temp_file:
                        temp_file.write(pdf_data)
                        temp_path = temp_file.name
                    
                    # Extract with LlamaParse
                    result = self._safe_extract(agent, temp_path)
                    extracted_data = result.data
                    
                    os.unlink(temp_path)
                    
                    # Process extracted data
                    rows = self._process_extracted_data(extracted_data, file)
                    
                    if rows:
                        self._save_to_sheets(config['spreadsheet_id'], config['sheet_range'], rows)
                        rows_added += len(rows)
                        processed_count += 1
                        logger.info(f"Processed {file['name']} - added {len(rows)} rows")
                    else:
                        logger.info(f"No data extracted from {file['name']}")
                    
                except Exception as e:
                    logger.error(f"Failed to process {file['name']}: {str(e)}")
            
            # Count unique files in Drive and Sheet after workflow
            drive_count = self.count_unique_files_in_drive(config['drive_folder_id'])
            sheet_count = self.count_unique_files_in_sheet(config['spreadsheet_id'], config['sheet_range'])
            
            logger.info("=" * 60)
            logger.info(f"{workflow_name} completed! Processed {processed_count} PDFs, added {rows_added} rows")
            logger.info(f"Unique files in Drive: {drive_count}")
            logger.info(f"Unique entries in Sheet: {sheet_count}")
            logger.info("=" * 60)
            
            # Log to sheet
            self.log_workflow(
                workflow_name, 
                workflow_start, 
                len(pdf_files), 
                processed_count, 
                "Success", 
                drive_count,
                sheet_count
            )
            
            return {'success': True, 'processed': processed_count}
            
        except Exception as e:
            logger.error(f"PDF workflow failed: {str(e)}")
            drive_count = 0
            sheet_count = 0
            self.log_workflow(workflow_name, workflow_start, 0, 0, f"Failed - {str(e)}", drive_count, sheet_count)
            return {'success': False, 'processed': 0}
    
    def count_unique_files_in_sheet(self, spreadsheet_id: str, sheet_range: str) -> int:
        """Count unique source_file entries in Google Sheet"""
        try:
            result = self.sheets_service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id,
                range=sheet_range,
                majorDimension="ROWS"
            ).execute()
            
            values = result.get('values', [])
            if not values or len(values) < 2:
                return 0
            
            headers = values[0]
            if "source_file" not in headers:
                logger.warning("No 'source_file' column found in sheet")
                return 0
            
            name_index = headers.index("source_file")
            unique_files = set()
            
            for row in values[1:]:
                if len(row) > name_index and row[name_index]:
                    unique_files.add(row[name_index])
            
            return len(unique_files)
            
        except Exception as e:
            logger.error(f"Failed to count unique files in sheet: {str(e)}")
            return 0
    
    def get_existing_source_files(self, spreadsheet_id: str, sheet_range: str) -> set:
        """Get set of existing source_file from Google Sheet"""
        try:
            result = self.sheets_service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id,
                range=sheet_range,
                majorDimension="ROWS"
            ).execute()
            
            values = result.get('values', [])
            if not values:
                return set()
            
            headers = values[0]
            if "source_file" not in headers:
                logger.warning("No 'source_file' column found in sheet")
                return set()
            
            name_index = headers.index("source_file")
            existing_names = {row[name_index] for row in values[1:] if len(row) > name_index and row[name_index]}
            
            return existing_names
            
        except Exception as e:
            logger.error(f"Failed to get existing file names: {str(e)}")
            return set()
    
    def _list_drive_files(self, folder_id: str, days_back: int = 7) -> List[Dict]:
        """List PDF files in Drive folder"""
        try:
            start_datetime = datetime.utcnow() - timedelta(days=days_back)
            start_str = start_datetime.strftime('%Y-%m-%dT00:00:00Z')
            
            query = f"'{folder_id}' in parents and mimeType='application/pdf' and trashed=false and createdTime > '{start_str}'"
            
            files = []
            page_token = None
            
            while True:
                results = self.drive_service.files().list(
                    q=query,
                    fields="nextPageToken, files(id, name, createdTime)",
                    pageToken=page_token
                ).execute()
                
                files.extend(results.get('files', []))
                page_token = results.get('nextPageToken')
                if not page_token:
                    break
            
            logger.info(f"Found {len(files)} PDF files in folder")
            return files
            
        except Exception as e:
            logger.error(f"Failed to list Drive files: {str(e)}")
            return []
    
    def _download_from_drive(self, file_id: str) -> bytes:
        """Download file from Drive"""
        try:
            request = self.drive_service.files().get_media(fileId=file_id)
            file_data = request.execute()
            return file_data
        except Exception as e:
            logger.error(f"Failed to download file {file_id}: {str(e)}")
            return b""
    
    def _safe_extract(self, agent, file_path: str, retries: int = 3, wait_time: int = 2):
        """Retry-safe extraction"""
        for attempt in range(1, retries + 1):
            try:
                return agent.extract(file_path)
            except Exception as e:
                if attempt < retries:
                    logger.warning(f"Extraction attempt {attempt} failed: {str(e)} - retrying...")
                    time.sleep(wait_time)
                else:
                    raise e
    
    def _process_extracted_data(self, extracted_data: Dict, file_info: Dict) -> List[Dict]:
        """Process extracted data into rows"""
        rows = []
        items = []
        
        if "items" in extracted_data:
            items = extracted_data["items"]
            for item in items:
                item["po_number"] = self._get_value(extracted_data, ["purchase_order_number", "po_number", "PO No"])
                item["vendor_invoice_number"] = self._get_value(extracted_data, ["supplier_bill_number", "vendor_invoice_number", "invoice_number"])
                item["supplier"] = self._get_value(extracted_data, ["supplier", "vendor", "Supplier Name"])
                item["shipping_address"] = self._get_value(extracted_data, ["Shipping Address", "receiver_address", "shipping_address"])
                item["grn_date"] = self._get_value(extracted_data, ["delivered_on", "grn_date"])
                item["source_file"] = file_info['name']
                item["processed_date"] = time.strftime("%Y-%m-%d %H:%M:%S")
                item["drive_file_id"] = file_info['id']
        elif "product_items" in extracted_data:
            items = extracted_data["product_items"]
            for item in items:
                item["po_number"] = self._get_value(extracted_data, ["purchase_order_number", "po_number", "PO No"])
                item["vendor_invoice_number"] = self._get_value(extracted_data, ["supplier_bill_number", "vendor_invoice_number", "invoice_number"])
                item["supplier"] = self._get_value(extracted_data, ["supplier", "vendor", "Supplier Name"])
                item["shipping_address"] = self._get_value(extracted_data, ["Shipping Address", "receiver_address", "shipping_address"])
                item["grn_date"] = self._get_value(extracted_data, ["delivered_on", "grn_date"])
                item["source_file"] = file_info['name']
                item["processed_date"] = time.strftime("%Y-%m-%d %H:%M:%S")
                item["drive_file_id"] = file_info['id']
        else:
            logger.warning(f"Skipping (no recognizable items key): {file_info['name']}")
            return rows
        
        # Clean items and add to rows
        for item in items:
            cleaned_item = {k: v for k, v in item.items() if v not in ["", None]}
            rows.append(cleaned_item)
        
        return rows
    
    def _get_value(self, data, possible_keys, default=""):
        """Return the first found key value from dict."""
        for key in possible_keys:
            if key in data:
                return data[key]
        return default
    
    def _save_to_sheets(self, spreadsheet_id: str, sheet_name: str, rows: List[Dict]):
        """Save data to Google Sheets with proper header management (append only, no replacement)"""
        try:
            if not rows:
                return
            
            # Get existing headers and data
            existing_headers = self._get_sheet_headers(spreadsheet_id, sheet_name)
            
            # Get all unique headers from new data
            new_headers = list(set().union(*(row.keys() for row in rows)))
            
            # Combine headers (existing + new unique ones)
            if existing_headers:
                all_headers = existing_headers.copy()
                for header in new_headers:
                    if header not in all_headers:
                        all_headers.append(header)
                
                # Update headers if new ones were added
                if len(all_headers) > len(existing_headers):
                    self._update_headers(spreadsheet_id, sheet_name, all_headers)
            else:
                # No existing headers, create them
                all_headers = new_headers
                self._update_headers(spreadsheet_id, sheet_name, all_headers)
            
            # Append new rows
            values = [[row.get(h, "") for h in all_headers] for row in rows]
            self._append_to_google_sheet(spreadsheet_id, sheet_name, values)
            
        except Exception as e:
            logger.error(f"Failed to save to sheets: {str(e)}")
    
    def _get_sheet_headers(self, spreadsheet_id: str, sheet_name: str) -> List[str]:
        """Get existing headers from Google Sheet"""
        try:
            result = self.sheets_service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id,
                range=f"{sheet_name}!A1:Z1",
                majorDimension="ROWS"
            ).execute()
            values = result.get('values', [])
            return values[0] if values else []
        except Exception as e:
            logger.info(f"No existing headers found: {str(e)}")
            return []
    
    def _update_headers(self, spreadsheet_id: str, sheet_name: str, headers: List[str]) -> bool:
        """Update the header row with new columns"""
        try:
            body = {'values': [headers]}
            result = self.sheets_service.spreadsheets().values().update(
                spreadsheetId=spreadsheet_id,
                range=f"{sheet_name}!A1:{chr(64 + len(headers))}1",
                valueInputOption='USER_ENTERED',
                body=body
            ).execute()
            logger.info(f"Updated headers with {len(headers)} columns")
            return True
        except Exception as e:
            logger.error(f"Failed to update headers: {str(e)}")
            return False
    
    def _append_to_google_sheet(self, spreadsheet_id: str, range_name: str, values: List[List[Any]]) -> bool:
        """Append data to a Google Sheet with retry mechanism"""
        max_retries = 3
        wait_time = 2
        
        for attempt in range(1, max_retries + 1):
            try:
                body = {'values': values}
                result = self.sheets_service.spreadsheets().values().append(
                    spreadsheetId=spreadsheet_id, 
                    range=range_name,
                    valueInputOption='USER_ENTERED', 
                    body=body
                ).execute()
                
                updated_cells = result.get('updates', {}).get('updatedCells', 0)
                logger.info(f"Appended {updated_cells} cells to Google Sheet")
                return True
            except Exception as e:
                if attempt < max_retries:
                    logger.warning(f"Failed to append to Google Sheet (attempt {attempt}/{max_retries}): {str(e)}")
                    time.sleep(wait_time)
                else:
                    logger.error(f"Failed to append to Google Sheet after {max_retries} attempts: {str(e)}")
                    return False
        return False
    
    def log_workflow(self, workflow_name: str, start_time: datetime, 
                     total_items: int, processed_items: int, status: str, 
                     drive_count: int, sheet_count: int):
        """Log workflow execution to workflow_logs sheet"""
        try:
            config = self.config.get('logging', {})
            spreadsheet_id = config.get('spreadsheet_id', self.config['pdf_workflow']['spreadsheet_id'])
            log_sheet = config.get('log_sheet', 'workflow_logs')
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            log_entry = [
                workflow_name,
                start_time.strftime("%Y-%m-%d %H:%M:%S"),
                end_time.strftime("%Y-%m-%d %H:%M:%S"),
                duration,
                total_items,
                processed_items,
                status,
                drive_count,
                sheet_count,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ]
            
            # Ensure log sheet exists and has headers
            headers = [
                'workflow_name', 'start_time', 'end_time', 'duration_seconds',
                'total_items', 'processed_items', 'status', 'unique_drive_files', 'unique_sheet_files', 'timestamp'
            ]
            self._ensure_sheet_exists(spreadsheet_id, log_sheet, headers)
            
            # Append log entry
            self._append_to_google_sheet(spreadsheet_id, log_sheet, [log_entry])
            
            logger.info(f"Logged workflow: {workflow_name} - {status}")
            
        except Exception as e:
            logger.error(f"Failed to log workflow: {str(e)}")
    
    def _save_detailed_logs(self):
        """Save collected detailed logs to detailed_logs sheet"""
        try:
            if not self.logs:
                return
            
            config = self.config.get('logging', {})
            spreadsheet_id = config.get('spreadsheet_id', self.config['pdf_workflow']['spreadsheet_id'])
            sheet_name = config.get('detailed_log_sheet', 'detailed_logs')
            
            headers = ['Timestamp', 'Workflow', 'Level', 'Message']
            self._ensure_sheet_exists(spreadsheet_id, sheet_name, headers)
            
            self._append_to_google_sheet(spreadsheet_id, sheet_name, self.logs)
            
            logger.info(f"Saved {len(self.logs)} detailed log entries to {sheet_name}")
            self.logs = []  # Clear after saving
            
        except Exception as e:
            logger.error(f"Failed to save detailed logs: {str(e)}")
    
    def _ensure_sheet_exists(self, spreadsheet_id: str, sheet_name: str, headers: List[str]):
        """Ensure sheet exists with proper headers"""
        try:
            # Check if sheet exists
            spreadsheet = self.sheets_service.spreadsheets().get(
                spreadsheetId=spreadsheet_id
            ).execute()
            
            sheets = spreadsheet.get('sheets', [])
            sheet_exists = any(s['properties']['title'] == sheet_name for s in sheets)
            
            if not sheet_exists:
                # Create the sheet
                request_body = {
                    'requests': [{
                        'addSheet': {
                            'properties': {
                                'title': sheet_name
                            }
                        }
                    }]
                }
                self.sheets_service.spreadsheets().batchUpdate(
                    spreadsheetId=spreadsheet_id,
                    body=request_body
                ).execute()
                logger.info(f"Created sheet: {sheet_name}")
            
            # Check if headers exist
            existing_headers = self._get_sheet_headers(spreadsheet_id, sheet_name)
            if not existing_headers:
                self._update_headers(spreadsheet_id, sheet_name, headers)
                logger.info(f"Added headers to sheet: {sheet_name}")
            
        except Exception as e:
            logger.error(f"Failed to ensure sheet exists: {str(e)}")
    
    def _save_remaining_files(self):
        """Check for and save remaining files not processed in sheet"""
        try:
            pdf_config = self.config['pdf_workflow']
            spreadsheet_id = pdf_config['spreadsheet_id']
            drive_folder_id = pdf_config['drive_folder_id']  # PDFs folder
            sheet_range = pdf_config['sheet_range']
            
            drive_count = self.count_unique_files_in_drive(drive_folder_id)
            sheet_count = self.count_unique_files_in_sheet(spreadsheet_id, sheet_range)
            
            if sheet_count < drive_count:
                drive_names = self.get_all_drive_pdf_names(drive_folder_id)
                sheet_names = self.get_existing_source_files(spreadsheet_id, sheet_range)
                remaining = list(drive_names - sheet_names)
                
                if remaining:
                    sheet_name = "remaining_files"
                    headers = ['file_name']
                    self._ensure_sheet_exists(spreadsheet_id, sheet_name, headers)
                    
                    values = [[f] for f in sorted(remaining)]
                    self._append_to_google_sheet(spreadsheet_id, sheet_name, values)
                    
                    logger.info(f"Saved {len(remaining)} remaining files to {sheet_name}")
            
        except Exception as e:
            logger.error(f"Failed to save remaining files: {str(e)}")
    
    def run_workflows(self):
        """Run both workflows in sequence"""
        logger.info("\n" + "=" * 80)
        logger.info("ZEPTO AUTOMATION - SCHEDULED RUN")
        logger.info(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info("=" * 80 + "\n")
        
        self.current_workflow = "Gmail to Drive"
        
        # Authenticate
        if not self.authenticate():
            logger.error("Authentication failed. Exiting...")
            self._save_detailed_logs()
            return
        
        # Run Gmail to Drive workflow
        gmail_result = self.process_gmail_workflow()
        
        if gmail_result['success']:
            logger.info("\nWaiting 5 seconds before starting PDF workflow...\n")
            time.sleep(5)
            
            self.current_workflow = "Drive to Sheet"
            
            # Run Drive to Sheet workflow
            pdf_result = self.process_pdf_workflow()
            
            if pdf_result['success']:
                self._save_remaining_files()
                logger.info("\n" + "=" * 80)
                logger.info("ALL WORKFLOWS COMPLETED SUCCESSFULLY!")
                logger.info("=" * 80 + "\n")
            else:
                logger.error("\n" + "=" * 80)
                logger.error("PDF WORKFLOW FAILED!")
                logger.error("=" * 80 + "\n")
        else:
            logger.error("\n" + "=" * 80)
            logger.error("GMAIL WORKFLOW FAILED - SKIPPING PDF WORKFLOW")
            logger.error("=" * 80 + "\n")
        
        self._save_detailed_logs()


def run_scheduled_job():
    """Function to run on schedule"""
    try:
        automation = ZeptoAutomationTerminal()
        automation.run_workflows()
    except Exception as e:
        logger.error(f"Scheduled job failed: {str(e)}")


def main():
    """Main function with scheduler"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Zepto Automation - Terminal Version')
    parser.add_argument('--run-once', action='store_true', 
                       help='Run workflows once and exit')
    parser.add_argument('--schedule', type=int, default=3,
                       help='Schedule interval in hours (default: 3)')
    
    args = parser.parse_args()
    
    if args.run_once:
        # Run once and exit
        logger.info("Running workflows once...")
        automation = ZeptoAutomationTerminal()
        automation.run_workflows()
    else:
        # Run on schedule
        logger.info(f"Starting Zepto Automation with {args.schedule}-hour schedule")
        logger.info("Press Ctrl+C to stop")
        
        # Schedule the job
        schedule.every(args.schedule).hours.do(run_scheduled_job)
        
        # Run immediately on start
        logger.info("Running initial workflow execution...")
        run_scheduled_job()
        
        # Keep running scheduled jobs
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute


if __name__ == "__main__":

    main()
