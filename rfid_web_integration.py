import threading
import time
import json
import sqlite3
from datetime import datetime
import logging

# Set up logging so we can see what's happening
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ScannerCoordinator:
    """
    The main coordinator that makes sure console and web play nicely together.
    Only one can use the scanner at a time, and everyone sees the same results.
    """

    def __init__(self):
        # Core components
        self.scanner = None
        self.ai_analyzer = None
        self.scanner_lock = threading.Lock()

        # Current state
        self.is_scanning = False
        self.current_user = "nobody"  # "console", "web", or "nobody"

        # Callbacks for real-time updates
        self.callbacks = []

        # Recent scan storage
        self.recent_scans = []

        # Web helper for sharing console results
        self.web_helper = None

        # Simple statistics
        self.stats = {
            'total_scans': 0,
            'successful_scans': 0,
            'failed_scans': 0,
            'risk_counts': {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0}
        }

        # Set up shared database
        self._setup_database()

        logger.info("Scanner coordinator ready")

    def register_web_helper(self, web_helper):
        """Register web helper for sharing console results."""
        self.web_helper = web_helper
        logger.info("Web helper registered for console-to-web sharing")

    def _setup_database(self):
        """Set up SQLite database for shared data storage."""
        try:
            conn = sqlite3.connect("shared_scans.db", timeout=10.0)
            cursor = conn.cursor()

            # Table for storing all scans
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS shared_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    source TEXT,
                    card_uid TEXT,
                    risk_level TEXT,
                    vulnerability_score INTEGER,
                    vulnerabilities_found INTEGER,
                    card_type TEXT,
                    detection_time REAL,
                    findings TEXT,
                    ai_analysis TEXT,
                    raw_data TEXT
                )
            ''')

            # Table for system status
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_status (
                    id INTEGER PRIMARY KEY,
                    scanner_status TEXT,
                    current_user TEXT,
                    is_scanning INTEGER,
                    last_update TEXT
                )
            ''')

            # Initialize system status
            cursor.execute('''
                INSERT OR REPLACE INTO system_status
                (id, scanner_status, current_user, is_scanning, last_update)
                VALUES (1, 'ready', 'nobody', 0, ?)
            ''', (datetime.now().isoformat(),))

            conn.commit()
            conn.close()

            logger.info("Database ready")

        except Exception as e:
            logger.error(f"Database setup failed: {e}")

    def register_scanner(self, scanner):
        """Register the RFID scanner for shared use."""
        with self.scanner_lock:
            if self.scanner is None:
                self.scanner = scanner
                logger.info("Scanner registered")
                return True
            else:
                logger.warning("Scanner already registered")
                return False

    def register_ai_analyzer(self, ai_analyzer):
        """Register the AI analyzer for enhanced analysis."""
        self.ai_analyzer = ai_analyzer
        logger.info("AI analyzer registered")

    def add_callback(self, callback_function):
        """Add a function to call when scans complete."""
        self.callbacks.append(callback_function)
        logger.info(f"Added callback: {callback_function.__name__}")

    def remove_callback(self, callback_function):
        """Remove a callback function."""
        if callback_function in self.callbacks:
            self.callbacks.remove(callback_function)
            logger.info(f"Removed callback: {callback_function.__name__}")

    def _notify_callbacks(self, result):
        """Tell all callbacks about scan results."""
        for callback in self.callbacks:
            try:
                callback(result)
            except Exception as e:
                logger.error(f"Callback failed: {e}")

    def _update_system_status(self, status, user):
        """Update system status in database."""
        try:
            conn = sqlite3.connect("shared_scans.db", timeout=10.0)
            cursor = conn.cursor()

            cursor.execute('''
                UPDATE system_status
                SET scanner_status = ?, current_user = ?, is_scanning = ?, last_update = ?
                WHERE id = 1
            ''', (status, user, int(self.is_scanning), datetime.now().isoformat()))

            conn.commit()
            conn.close()

        except Exception as e:
            logger.error(f"Status update failed: {e}")

    def _save_scan_result(self, result, source):
        """Save scan result with ACCURATE confirmed vulnerability count - NO ASSUMPTIONS"""
        try:
            conn = sqlite3.connect("shared_scans.db", timeout=10.0)
            cursor = conn.cursor()

            # CRITICAL FIX: Extract CONFIRMED vulnerability count only
            confirmed_count = 0

            # Priority 1: Use explicit confirmed count from result
            if 'confirmed_vulnerabilities' in result:
                confirmed_count = result['confirmed_vulnerabilities']
            elif 'vulnerabilities_found' in result:
                confirmed_count = result['vulnerabilities_found']

            # Priority 2: Extract from raw_assessment if available
            raw_assessment = result.get('raw_assessment', {})
            if raw_assessment and isinstance(raw_assessment, dict):
                confirmed_findings = raw_assessment.get('confirmed_findings', [])
                if confirmed_findings:
                    actual_confirmed_count = len(confirmed_findings)
                    confirmed_count = actual_confirmed_count
                    logger.info(f"Using actual confirmed count from raw_assessment: {actual_confirmed_count}")

            # DUPLICATE PREVENTION: Check if this scan already exists
            card_uid = result.get('card_uid', '')
            timestamp = result.get('timestamp', datetime.now().isoformat())

            cursor.execute('''
                SELECT COUNT(*) FROM shared_scans
                WHERE card_uid = ? AND datetime(timestamp) > datetime('now', '-30 seconds')
            ''', (card_uid,))

            existing_count = cursor.fetchone()[0]

            if existing_count > 0:
                logger.info(f"Updating existing scan for card {card_uid} with accurate vulnerability count")

                # Update with accurate data
                cursor.execute('''
                    UPDATE shared_scans
                    SET vulnerabilities_found = ?, ai_analysis = ?, raw_data = ?
                    WHERE card_uid = ? AND datetime(timestamp) > datetime('now', '-30 seconds')
                ''', (confirmed_count, result.get('_complete_console_report', ''), json.dumps(result), card_uid))

                conn.commit()
                conn.close()
                logger.info(f"Updated scan with {confirmed_count} confirmed vulnerabilities")
                return

            # Prepare AI analysis with complete console report priority
            ai_analysis_str = ''
            if result.get('_complete_console_report'):
                ai_analysis_str = result.get('_complete_console_report')
                logger.info("Using complete console report for database storage")
            elif result.get('_full_ai_results'):
                ai_analysis_str = result.get('_full_ai_results')
                logger.info("Using complete AI results for database storage")
            elif result.get('ai_analysis_text'):
                ai_analysis_str = result.get('ai_analysis_text')
                logger.info("Using AI analysis text for database storage")
            else:
                ai_analysis_str = f"Professional security assessment completed for {result.get('card_type', 'RFID card')}"
                logger.info("Using fallback assessment info for database storage")

            # Convert complex objects to JSON strings before saving
            findings_json = json.dumps(result.get('findings', []))
            raw_data_json = json.dumps(result)

            # CRITICAL: Save with CONFIRMED vulnerability count only
            cursor.execute('''
                INSERT INTO shared_scans
                (timestamp, source, card_uid, risk_level, vulnerability_score,
                vulnerabilities_found, card_type, detection_time, findings,
                ai_analysis, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                timestamp,
                source,
                card_uid,
                result.get('risk_level', ''),
                result.get('vulnerability_score', 0),
                confirmed_count,  # FIXED: Confirmed vulnerabilities only
                result.get('card_type', ''),
                result.get('detection_time', 0.0),
                findings_json,
                ai_analysis_str,
                raw_data_json
            ))

            conn.commit()
            conn.close()

            # Update our statistics
            self._update_statistics(result)

            logger.info(f"Saved scan from {source} with {confirmed_count} CONFIRMED vulnerabilities (not total vulnerabilities)")
            logger.info(f"Analysis length: {len(ai_analysis_str)} characters")

        except Exception as e:
            logger.error(f"Could not save scan: {e}")
            import traceback
            logger.error(f"Error traceback: {traceback.format_exc()}")

    def _update_statistics(self, result):
        """Update our running statistics."""
        self.stats['total_scans'] += 1

        if result.get('status') == 'completed':
            self.stats['successful_scans'] += 1
            risk_level = result.get('risk_level', 'MEDIUM')
            if risk_level in self.stats['risk_counts']:
                self.stats['risk_counts'][risk_level] += 1
        else:
            self.stats['failed_scans'] += 1

    def start_scan(self, requester, timeout=15):
        """Start scanning with ACCURATE vulnerability counting - NO ASSUMPTIONS"""

        # [Previous code for checking scanner availability remains the same...]

        # Check if someone else is already scanning
        if self.is_scanning:
            return {
                'status': 'error',
                'message': f'Scanner is busy - {self.current_user} is using it right now',
                'current_user': self.current_user
            }

        # Check if scanner is available
        if not self.scanner:
            return {
                'status': 'error',
                'message': 'Scanner hardware not available',
                'available': False
            }

        # Get exclusive access to the scanner
        with self.scanner_lock:
            # Double-check in case someone else got in
            if self.is_scanning:
                return {
                    'status': 'error',
                    'message': f'Scanner is busy - {self.current_user} is using it right now',
                    'current_user': self.current_user
                }

            # Set our scanning state
            self.is_scanning = True
            self.current_user = requester
            self._update_system_status('scanning', requester)

            logger.info(f"Scan started by {requester}")

            try:
                # Do the actual RFID scan
                result = self.scanner.perform_professional_assessment(timeout=timeout)

                if result and result != 0 and isinstance(result, dict):

                    # CRITICAL FIX: Get ACCURATE summary with confirmed count only
                    summary_values = self.scanner.generate_realtime_assessment_summary(result)

                    # Handle both dictionary and tuple formats
                    if isinstance(summary_values, dict):
                        card_type = summary_values.get('card_type', 'Unknown Card')
                        risk_level = summary_values.get('risk_level', 'MEDIUM')
                        vulnerability_score = summary_values.get('vulnerability_score', 50)
                        confirmed_count = summary_values.get('confirmed_count', 0)
                        theoretical_count = summary_values.get('theoretical_count', 0)
                    else:
                        # Legacy tuple handling
                        card_type = summary_values[0] if len(summary_values) > 0 else "Unknown Card"
                        risk_level = summary_values[1] if len(summary_values) > 1 else "MEDIUM"
                        vulnerability_score = summary_values[2] if len(summary_values) > 2 else 50
                        confirmed_count = summary_values[3] if len(summary_values) > 3 else 0
                        theoretical_count = 0

                    # CRITICAL: Extract ACTUAL confirmed vulnerability count from raw assessment
                    raw_assessment = result
                    actual_confirmed_findings = raw_assessment.get('confirmed_findings', [])
                    actual_confirmed_count = len(actual_confirmed_findings)

                    # Use the ACTUAL count from the assessment
                    final_confirmed_count = actual_confirmed_count

                    logger.info(f"DEBUG: Confirmed vulnerabilities - Summary: {confirmed_count}, Actual: {actual_confirmed_count}, Using: {final_confirmed_count}")

                    # Generate realistic summary for integration
                    realistic_summary = {
                        'uid': str(result.get('target_analysis', {}).get('uid', 'Unknown')),
                        'card_type': card_type,
                        'risk_level': risk_level,
                        'vulnerability_score': vulnerability_score,
                        'vulnerability_count': final_confirmed_count,  # FIXED: Use actual confirmed count
                        'detection_time': result.get('metadata', {}).get('detection_time', 0.0),
                        'uid_entropy': result.get('target_analysis', {}).get('uid_entropy', {}).get('shannon_entropy', 0.0),
                        'findings': [
                            finding.get('finding', 'Security issue')
                            for finding in actual_confirmed_findings  # Use actual findings
                        ]
                    }

                    # Get AI analysis (enhanced to get complete analysis)
                    ai_analysis = ""
                    complete_ai_analysis = ""

                    # Check for complete AI analysis that was already generated
                    if result.get('_complete_console_report'):
                        complete_ai_analysis = result.get('_complete_console_report')
                        ai_analysis = "Complete professional assessment with AI analysis available"
                    elif result.get('_full_ai_results'):
                        complete_ai_analysis = result.get('_full_ai_results')
                        ai_analysis = "AI analysis completed - view full report for details"
                    elif result.get('ai_analysis_text'):
                        complete_ai_analysis = result.get('ai_analysis_text')
                        ai_analysis = "AI analysis completed - view full report for details"
                    else:
                        # Generate meaningful AI analysis from REAL scan data only
                        findings = realistic_summary.get('findings', [])
                        if findings and len(findings) > 0:
                            findings_text = ', '.join(findings[:3])
                            if len(findings) > 3:
                                findings_text += '...'
                            ai_analysis = (
                                f"AI Security Analysis: {realistic_summary['risk_level'].lower()} "
                                f"risk assessment with {realistic_summary['vulnerability_score']}/100 "
                                f"vulnerability score. Detected {len(findings)} confirmed security vulnerabilities: "
                                f"{findings_text}"
                            )
                            complete_ai_analysis = ai_analysis
                        else:
                            ai_analysis = (
                                f"AI Security Analysis: {realistic_summary['risk_level'].lower()} "
                                f"risk profile with {realistic_summary['vulnerability_score']}/100 "
                                f"vulnerability score. Comprehensive security assessment completed."
                            )
                            complete_ai_analysis = ai_analysis

                    # CRITICAL FIX: Package with ACCURATE confirmed vulnerability count
                    scan_result = {
                        'status': 'completed',
                        'source': requester,
                        'card_uid': realistic_summary['uid'],
                        'risk_level': realistic_summary['risk_level'],
                        'vulnerability_score': realistic_summary['vulnerability_score'],
                        'vulnerabilities_found': final_confirmed_count,  # FIXED: Confirmed count only
                        'confirmed_vulnerabilities': final_confirmed_count,  # Explicit confirmed count
                        'theoretical_vulnerabilities': len(result.get('theoretical_vulnerabilities', [])),  # Separate theoretical count
                        'card_type': realistic_summary['card_type'],
                        'detection_time': realistic_summary['detection_time'],
                        'timestamp': datetime.now().isoformat(),
                        'findings': realistic_summary['findings'],
                        'ai_analysis': ai_analysis,
                        '_complete_console_report': result.get('_complete_console_report', ''),
                        '_full_ai_results': complete_ai_analysis,
                        'ai_analysis_text': complete_ai_analysis,
                        'entropy': realistic_summary.get('uid_entropy', 0.0),
                        'session_id': f"{requester}_{int(time.time())}",
                        'raw_assessment': result  # Store complete assessment for web dashboard
                    }

                    logger.info(f"Scan result created with {final_confirmed_count} confirmed vulnerabilities (not {len(result.get('theoretical_vulnerabilities', []))} total)")

                    # Save the result with accurate data
                    self._save_scan_result(scan_result, requester)

                    # Add to recent scans (keep last 100)
                    self.recent_scans.append(scan_result)
                    if len(self.recent_scans) > 100:
                        self.recent_scans.pop(0)

                    # Console to web sharing
                    if requester == "console" and self.web_helper:
                        logger.info("Console scan completed - sharing with web dashboard...")
                        shared_result = self.web_helper.share_console_result_with_web(result)
                        if shared_result:
                            logger.info(f"Console result shared with dashboard: {shared_result['card_uid']}")
                        else:
                            logger.warning("Failed to share console result with dashboard")

                    # Tell everyone about the result
                    self._notify_callbacks(scan_result)

                    logger.info(f"Scan completed by {requester}: {realistic_summary['card_type']} with {final_confirmed_count} confirmed vulnerabilities")

                    return scan_result

                else:
                    # No card was detected
                    no_card_result = {
                        'status': 'no_card',
                        'source': requester,
                        'message': 'No card detected - try holding it closer to the reader',
                        'timestamp': datetime.now().isoformat(),
                        'session_id': f"{requester}_{int(time.time())}"
                    }

                    logger.info(f"No card detected for {requester}")
                    return no_card_result

            except Exception as e:
                logger.error(f"Scan failed for {requester}: {e}")
                import traceback
                logger.error(f"Error traceback: {traceback.format_exc()}")
                return {
                    'status': 'error',
                    'source': requester,
                    'message': f'Scan failed: {str(e)}',
                    'timestamp': datetime.now().isoformat()
                }

            finally:
                # Always release the scanner when done
                self.is_scanning = False
                self.current_user = "nobody"
                self._update_system_status('ready', 'nobody')
                logger.info(f"Scanner released by {requester}")

    def stop_scan(self, requester):
        """
        Stop the current scanning operation.

        Args:
            requester: Who wants to stop the scan

        Returns:
            Status dictionary
        """

        if not self.is_scanning:
            return {
                'status': 'info',
                'message': 'No scan is currently running'
            }

        if self.current_user != requester:
            return {
                'status': 'error',
                'message': f'Cannot stop scan - it was started by {self.current_user}',
                'current_user': self.current_user
            }

        # Force stop the scan
        self.is_scanning = False
        self.current_user = "nobody"
        self._update_system_status('ready', 'nobody')

        logger.info(f"Scan stopped by {requester}")

        return {
            'status': 'stopped',
            'message': 'Scan stopped successfully'
        }

    def get_status(self):
        """Get current scanner and system status."""
        return {
            'available': self.scanner is not None,
            'is_scanning': self.is_scanning,
            'current_user': self.current_user,
            'scanner_connected': self.scanner.test_scanner_connection() if self.scanner else False,
            'ai_available': self.ai_analyzer is not None
        }

    def get_statistics(self):
        """Get comprehensive scan statistics."""
        conn = None
        try:
            conn = sqlite3.connect("shared_scans.db")
            cursor = conn.cursor()

            # Get total scans from database
            cursor.execute('SELECT COUNT(*) FROM shared_scans')
            total_scans = cursor.fetchone()[0]

            # Get risk distribution
            cursor.execute('SELECT risk_level, COUNT(*) FROM shared_scans GROUP BY risk_level')
            risk_distribution = dict([
                (k, v) for k, v in cursor.fetchall() if k is not None
            ])

            # Get average vulnerability score
            cursor.execute("""
                SELECT AVG(vulnerability_score) FROM shared_scans
                WHERE vulnerability_score IS NOT NULL AND vulnerability_score > 0
            """)
            avg_score = cursor.fetchone()[0] or 0

            # Get scans by source
            cursor.execute('SELECT source, COUNT(*) FROM shared_scans GROUP BY source')
            scans_by_source = dict([
                (k, v) for k, v in cursor.fetchall() if k is not None
            ])

            return {
                'total_scans': total_scans,
                'successful_scans': total_scans,
                'risk_distribution': risk_distribution,
                'average_vulnerability_score': round(float(avg_score or 0), 1) if avg_score is not None else 0,
                'scans_by_source': scans_by_source,
                'scanner_status': 'Ready' if self.scanner else 'Not Available',
                'current_state': 'Scanning' if self.is_scanning else 'Ready',
                'current_user': self.current_user if self.is_scanning else 'Nobody'
            }

        except Exception as e:
            logger.error(f"Could not get statistics: {e}")
            return {
                'total_scans': 0,
                'error': str(e)
            }
        finally:
            if conn:
                conn.close()

    def get_scan_history(self, limit=50):
        """Get recent scan history."""
        try:
            conn = sqlite3.connect("shared_scans.db", timeout=10.0)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT timestamp, source, card_uid, risk_level, vulnerability_score,
                       vulnerabilities_found, card_type, detection_time
                FROM shared_scans
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))

            results = cursor.fetchall()
            conn.close()

            history = []
            for row in results:
                history.append({
                    'timestamp': row[0],
                    'source': row[1],
                    'card_uid': row[2],
                    'risk_level': row[3],
                    'vulnerability_score': row[4],
                    'vulnerabilities_found': row[5],
                    'card_type': row[6],
                    'detection_time': row[7]
                })

            return {'history': history}

        except Exception as e:
            logger.error(f"Could not get scan history: {e}")
            return {'history': [], 'error': str(e)}

    def get_scan_history_with_indices(self, limit=50):
        """Get recent scan history with array indices as IDs and AI analysis availability."""
        try:
            conn = sqlite3.connect("shared_scans.db", timeout=10.0)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT timestamp, source, card_uid, risk_level, vulnerability_score,
                       vulnerabilities_found, card_type, detection_time, ai_analysis
                FROM shared_scans
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))

            results = cursor.fetchall()
            conn.close()

            history = []
            for i, row in enumerate(results):
                scan_data = {
                    'id': i,  # Use array index as ID for web interface
                    'timestamp': row[0],
                    'source': row[1],
                    'card_uid': row[2],
                    'risk_level': row[3],
                    'vulnerability_score': row[4],
                    'vulnerabilities_found': row[5],
                    'card_type': row[6],
                    'detection_time': row[7],
                    'has_ai_analysis': False  # Default to False
                }

                # Check if AI analysis is available
                ai_analysis = row[8] if len(row) > 8 else ''
                if ai_analysis and len(ai_analysis) > 50:  # Has substantial AI analysis
                    scan_data['has_ai_analysis'] = True

                # Also check recent_scans for complete AI analysis
                for recent_scan in self.recent_scans:
                    if (recent_scan.get('card_uid') == scan_data['card_uid'] and
                        recent_scan.get('timestamp') == scan_data['timestamp']):
                        if (recent_scan.get('_complete_console_report') or
                            recent_scan.get('_full_ai_results')):
                            scan_data['has_ai_analysis'] = True
                        break

                history.append(scan_data)

            return {'history': history}

        except Exception as e:
            logger.error(f"Could not get scan history with indices: {e}")
            return {'history': [], 'error': str(e)}

    def get_scan_by_array_index(self, index):
        """Get scan data by array index (for web interface downloads)."""
        try:
            history_data = self.get_scan_history_with_indices(500)
            history = history_data.get('history', [])

            if 0 <= index < len(history):
                scan = history[index]

                # Add complete console report and AI analysis if available in recent_scans
                for recent_scan in self.recent_scans:
                    if (recent_scan.get('card_uid') == scan.get('card_uid') and
                        recent_scan.get('timestamp') == scan.get('timestamp')):
                        scan['_complete_console_report'] = recent_scan.get('_complete_console_report', '')
                        scan['_full_ai_results'] = recent_scan.get('_full_ai_results', '')
                        scan['ai_analysis_text'] = recent_scan.get('ai_analysis_text', '')
                        scan['findings'] = recent_scan.get('findings', [])
                        scan['raw_assessment'] = recent_scan.get('raw_assessment', {})
                        break

                # If no complete console report in recent_scans, try to get from database
                if not scan.get('_complete_console_report'):
                    try:
                        conn = sqlite3.connect("shared_scans.db", timeout=10.0)
                        cursor = conn.cursor()

                        cursor.execute('''
                            SELECT ai_analysis, findings FROM shared_scans
                            WHERE card_uid = ? AND timestamp = ?
                        ''', (scan.get('card_uid'), scan.get('timestamp')))

                        result = cursor.fetchone()
                        if result:
                            scan['_complete_console_report'] = result[0] or ''
                            scan['_full_ai_results'] = result[0] or ''
                            try:
                                scan['findings'] = json.loads(result[1]) if result[1] else []
                            except:
                                scan['findings'] = []

                        conn.close()
                    except Exception as e:
                        logger.error(f"Error getting complete console report from database: {e}")

                return scan

            return None

        except Exception as e:
            logger.error(f"Error getting scan by array index {index}: {e}")
            return None

    def cleanup(self):
        """Clean up when shutting down."""
        self.is_scanning = False
        self.current_user = "nobody"
        self._update_system_status('shutdown', 'nobody')
        logger.info("Coordinator cleaned up")


# Global coordinator instance
_global_coordinator = None


def get_coordinator():
    """Get the shared coordinator instance."""
    global _global_coordinator
    if _global_coordinator is None:
        _global_coordinator = ScannerCoordinator()
    return _global_coordinator


def setup_integration(scanner=None, ai_analyzer=None):
    """
    Set up the integration system.

    Args:
        scanner: RFID scanner instance
        ai_analyzer: AI analyzer instance

    Returns:
        True if setup was successful
    """
    try:
        coordinator = get_coordinator()

        if scanner:
            coordinator.register_scanner(scanner)

        if ai_analyzer:
            coordinator.register_ai_analyzer(ai_analyzer)

        logger.info("Integration setup complete")
        return True

    except Exception as e:
        logger.error(f"Integration setup failed: {e}")
        return False


# Easy-to-use functions for other parts of the system

def start_scan(requester, timeout=15):
    """Start a scan using the coordinator."""
    return get_coordinator().start_scan(requester, timeout)


def stop_scan(requester):
    """Stop a scan using the coordinator."""
    return get_coordinator().stop_scan(requester)


def get_scanner_status():
    """Get current scanner status."""
    return get_coordinator().get_status()


def get_statistics():
    """Get scan statistics."""
    return get_coordinator().get_statistics()


def get_scan_history(limit=50):
    """Get recent scan history."""
    return get_coordinator().get_scan_history(limit)


def get_scan_history_with_indices(limit=50):
    """Get recent scan history with array indices as IDs."""
    return get_coordinator().get_scan_history_with_indices(limit)


def get_scan_by_array_index(index):
    """Get scan data by array index."""
    return get_coordinator().get_scan_by_array_index(index)


def add_callback(callback_function):
    """Add a callback for scan results."""
    get_coordinator().add_callback(callback_function)


def remove_callback(callback_function):
    """Remove a callback."""
    get_coordinator().remove_callback(callback_function)


def cleanup():
    """Clean up integration when shutting down."""
    global _global_coordinator
    if _global_coordinator:
        _global_coordinator.cleanup()
        _global_coordinator = None


# Helper classes for easy integration

class ConsoleHelper:
    """Makes it easy to integrate with console applications."""

    def __init__(self, console_app):
        self.console_app = console_app
        self.coordinator = get_coordinator()

        # Listen for web scans and show them in console
        self.coordinator.add_callback(self._handle_scan_result)

    def _handle_scan_result(self, result):
        """Show web scan results in console output."""
        if result.get('source') == 'web':
            print(f"\nWeb browser scan result:")
            print(f"   Card: {result.get('card_uid', 'Unknown')}")
            print(f"   Risk: {result.get('risk_level', 'Unknown')}")
            print(f"   Score: {result.get('vulnerability_score', 0)}/100")
            print()

    def scan_from_console(self, timeout=15):
        """Perform a scan from the console interface."""
        print("Looking for RFID cards...")
        result = self.coordinator.start_scan("console", timeout)

        if result.get('status') == 'completed':
            # The professional report and AI analysis were already printed during the scan
            # No need for additional console output as it's handled in perform_professional_assessment
            pass
        elif result.get('status') == 'no_card':
            print("No card detected - try holding it closer")
        elif result.get('status') == 'error':
            print(f"Scan failed: {result.get('message')}")

        return result


class WebHelper:
    """Makes it easy to integrate with web applications and share real scanner data."""

    def __init__(self, socketio=None):
        self.socketio = socketio
        self.coordinator = get_coordinator()
        self.shared_scan_data = None

        # Register this web helper with the coordinator for console-to-web sharing
        self.coordinator.register_web_helper(self)

        # Listen for console scans and send them to web clients
        if self.socketio:
            self.coordinator.add_callback(self._handle_scan_result)

    def share_console_result_with_web(self, assessment_result):
        """
        Share console scan results with the web dashboard in real-time.
        This ensures dashboard shows the SAME data as console.
        """
        try:
            if not assessment_result:
                return None

            logger.info("Sharing console scan result with web dashboard...")

            # Extract the professional assessment data (same as console shows)
            target_analysis = assessment_result.get('target_analysis', {})
            metadata = assessment_result.get('metadata', {})
            confirmed_findings = assessment_result.get('confirmed_findings', [])
            theoretical_vulns = assessment_result.get('theoretical_vulnerabilities', [])
            security_features = assessment_result.get('security_features', [])

            # Calculate risk level from CVSS scores (same calculation as console)
            total_cvss = sum(finding.get('cvss_score', 0) for finding in confirmed_findings)
            avg_cvss = total_cvss / len(confirmed_findings) if confirmed_findings else 0

            if avg_cvss >= 7.0:
                risk_level = "HIGH"
            elif avg_cvss >= 4.0:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"

            vulnerability_score = int(avg_cvss * 10) if avg_cvss > 0 else 0

            # CRITICAL FIX: Extract complete console report and AI analysis
            complete_console_report = ''
            complete_ai_analysis = ''

            # Priority 1: Complete console report
            if assessment_result.get('_complete_console_report'):
                complete_console_report = assessment_result.get('_complete_console_report')
            # Priority 2: Complete AI analysis
            elif assessment_result.get('_full_ai_results'):
                complete_ai_analysis = assessment_result.get('_full_ai_results')
            elif assessment_result.get('ai_analysis_text'):
                complete_ai_analysis = assessment_result.get('ai_analysis_text')
            else:
                # If no complete analysis found, use basic AI data
                ai_data = assessment_result.get('ai_analysis', {})
                if isinstance(ai_data, str):
                    complete_ai_analysis = ai_data
                else:
                    complete_ai_analysis = 'Professional security assessment completed'

            # Build the web result with SAME data as console shows
            web_result = {
                'status': 'completed',
                'card_uid': str(target_analysis.get('uid', 'Unknown')),
                'risk_level': risk_level,
                'vulnerability_score': vulnerability_score,
                'vulnerabilities_found': len(confirmed_findings),
                'card_type': target_analysis.get('estimated_type', 'RFID Card'),
                'detection_time': metadata.get('detection_time', 0.0),
                'timestamp': datetime.now().isoformat(),
                'findings': [
                    finding.get('finding', 'Security issue')
                    for finding in confirmed_findings
                ],
                'ai_analysis': assessment_result.get('ai_analysis', 'Professional security assessment completed'),
                'entropy': target_analysis.get('uid_entropy', {}).get('shannon_entropy', 0.0),

                # CRITICAL: Store complete console report and AI analysis for web dashboard
                '_complete_console_report': complete_console_report,
                '_full_ai_results': complete_ai_analysis,
                'ai_analysis_text': complete_ai_analysis,

                # Additional professional data (same as console report)
                'entropy_assessment': target_analysis.get('uid_entropy', {}).get('assessment', 'Unknown'),
                'randomness_quality': target_analysis.get('uid_entropy', {}).get('randomness_quality', 'Unknown'),
                'manufacturer': target_analysis.get('manufacturer_analysis', {}).get('name', 'Unknown'),
                'manufacturer_confidence': target_analysis.get('manufacturer_analysis', {}).get('confidence', 'LOW'),
                'confirmed_findings_count': len(confirmed_findings),
                'theoretical_vulns_count': len(theoretical_vulns),
                'security_features_count': len(security_features),
                'assessment_id': metadata.get('assessment_id', 'Unknown'),
                'frequency': target_analysis.get('frequency_confirmed', '13.56MHz'),
                'confirmed_findings_detailed': confirmed_findings,
                'theoretical_vulnerabilities': theoretical_vulns,
                'security_features': security_features
            }

            # Send to web dashboard immediately
            if self.socketio:
                logger.info(f"Sending to dashboard: {web_result['card_type']} - {web_result['risk_level']} risk")
                self.socketio.emit('scan_result', web_result)
                self.socketio.emit('scan_status', {
                    'status': 'completed',
                    'message': f"Console scan shared: {web_result['card_uid']}"
                })

            # Store in shared data for dashboard API
            self.shared_scan_data = web_result

            return web_result

        except Exception as e:
            logger.error(f"Error sharing console result with web: {e}")
            import traceback
            logger.error(f"Error traceback: {traceback.format_exc()}")
            return None

    def _handle_scan_result(self, result):
        """Send console scan results to web clients - ENHANCED REAL DATA SHARING."""
        if self.socketio and result.get('source') == 'console':
            # Extract additional detailed data from the raw assessment if available
            raw_assessment = result.get('raw_assessment', {})

            # Get detailed professional assessment data
            target_analysis = raw_assessment.get('target_analysis', {})
            confirmed_findings = raw_assessment.get('confirmed_findings', [])
            theoretical_vulns = raw_assessment.get('theoretical_vulnerabilities', [])
            security_features = raw_assessment.get('security_features', [])
            recommendations = raw_assessment.get('professional_recommendations', [])

            # Build detailed findings for web display
            detailed_findings = []
            for finding in confirmed_findings:
                detailed_findings.append({
                    'finding': finding.get('finding', 'Security issue'),
                    'severity': finding.get('severity', 'Unknown'),
                    'cvss_score': finding.get('cvss_score', 0),
                    'description': finding.get('description', ''),
                    'impact': finding.get('real_world_impact', ''),
                    'confidence': finding.get('confidence', 'Unknown'),
                    'evidence': finding.get('technical_evidence', ''),
                    'complexity': finding.get('exploitation_complexity', 'Unknown')
                })

            # Get entropy and manufacturer data
            entropy_data = target_analysis.get('uid_entropy', {})
            manufacturer_data = target_analysis.get('manufacturer_analysis', {})

            # Send the COMPLETE real-time assessment to web clients
            # This ensures web dashboard shows SAME detailed data as console
            enhanced_result = {
                'status': result.get('status'),
                'card_uid': result.get('card_uid'),
                'risk_level': result.get('risk_level'),
                'vulnerability_score': result.get('vulnerability_score'),
                'vulnerabilities_found': result.get('vulnerabilities_found'),
                'card_type': result.get('card_type'),
                'detection_time': result.get('detection_time'),
                'timestamp': result.get('timestamp'),
                'findings': result.get('findings', []),
                'ai_analysis': result.get('ai_analysis', ''),
                '_complete_console_report': result.get('_complete_console_report', ''),
                '_full_ai_results': result.get('_full_ai_results', ''),
                'ai_analysis_text': result.get('ai_analysis_text', ''),
                'entropy': result.get('entropy', 0.0),
                # Enhanced data from professional assessment
                'entropy_assessment': entropy_data.get('assessment', 'Unknown'),
                'randomness_quality': entropy_data.get('randomness_quality', 'Unknown'),
                'manufacturer': manufacturer_data.get('name', 'Unknown'),
                'manufacturer_confidence': manufacturer_data.get('confidence', 'LOW'),
                'confirmed_findings_count': len(confirmed_findings),
                'theoretical_vulns_count': len(theoretical_vulns),
                'security_features_count': len(security_features),
                'assessment_id': raw_assessment.get('metadata', {}).get('assessment_id', 'Unknown'),
                'frequency': target_analysis.get('frequency_confirmed', '13.56MHz'),
                'estimated_type': target_analysis.get('estimated_type', 'Unknown'),
                'detailed_findings': detailed_findings,
                'theoretical_vulnerabilities': theoretical_vulns,
                'security_features': security_features,
                'professional_recommendations': recommendations,
                # Timing analysis data
                'avg_response_time': target_analysis.get('timing_analysis', {}).get('average_response_time', 0.0),
                'timing_variance': target_analysis.get('timing_analysis', {}).get('timing_variance', 0.0),
                'timing_consistency': target_analysis.get('timing_analysis', {}).get('timing_consistency', 'Unknown')
            }

            # Notify web clients about console scans with full professional data
            self.socketio.emit('scan_result', enhanced_result)

            # Update scan status with detailed information
            self.socketio.emit('scan_status', {
                'status': 'completed',
                'message': (
                    f'Console scan completed: {result.get("card_type", "Unknown card")} - '
                    f'{result.get("risk_level", "Unknown")} risk - '
                    f'{result.get("vulnerabilities_found", 0)} issues found'
                )
            })

    def scan_from_web(self, timeout=15):
        """Start a scan from the web interface."""
        return self.coordinator.start_scan("web", timeout)

    def stop_web_scan(self):
        """Stop a web scan."""
        return self.coordinator.stop_scan("web")

    def get_dashboard_data(self):
        """Get all data needed for the web dashboard."""
        return {
            'status': self.coordinator.get_status(),
            'statistics': self.coordinator.get_statistics(),
            'history': self.coordinator.get_scan_history(20)
        }

    def get_scan_by_id(self, scan_id):
        """Get a specific scan by its position in history (for web dashboard AI analysis)"""
        try:
            # Use the optimized method that handles array indices properly
            return self.coordinator.get_scan_by_array_index(scan_id)

        except Exception as e:
            logger.error(f"Error getting scan by ID {scan_id}: {e}")
            return None

    def update_last_scan_with_ai_analysis(self, ai_analysis):
        """Update the last scan result with complete AI analysis"""
        try:
            # FIXED: Access recent_scans through the coordinator
            if self.coordinator.recent_scans:
                last_scan = self.coordinator.recent_scans[-1]
                last_scan['ai_analysis'] = ai_analysis
                last_scan['_full_ai_results'] = ai_analysis.get('complete_text', '')
                last_scan['ai_analysis_text'] = ai_analysis.get('complete_text', '')
                logger.info("Updated last scan with complete AI analysis")
        except Exception as e:
            logger.error(f"Failed to update last scan with AI analysis: {e}")


# Test the integration system
if __name__ == "__main__":
    print("Testing RFID Integration System...")

    # Test setup
    success = setup_integration()
    print(f"Setup: {'Success' if success else 'Failed'}")

    # Test status
    status = get_scanner_status()
    print(f"Status: {status}")

    # Test statistics
    stats = get_statistics()
    print(f"Statistics: {stats}")

    # Clean up
    cleanup()
    print("Test completed")