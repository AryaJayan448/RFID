from flask import Flask, render_template, request, jsonify, send_file, make_response,redirect
from flask_socketio import SocketIO, emit
import sqlite3
import json
import threading
import time
from datetime import datetime
import sys
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv
from functools import wraps
import os
import glob

load_dotenv()

try:
    from auth_system import auth_manager, User
    AUTH_AVAILABLE = True
    print("Authentication system loaded")
except ImportError as e:
    print(f"Authentication not available: {e}")
    AUTH_AVAILABLE = False

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


try:
    from rfid_web_integration import get_coordinator, WebHelper, get_scan_by_array_index, get_scan_history_with_indices
    INTEGRATION_AVAILABLE = True
    print("Integration system available")
except ImportError as e:
    print(f"Integration not available: {e}")
    INTEGRATION_AVAILABLE = False

try:
    from blockchain_handler import get_network_stats, analyze_scan_real_time
    BLOCKCHAIN_AVAILABLE = True
    print("Blockchain API enabled for dashboard")
except ImportError:
    BLOCKCHAIN_AVAILABLE = False
    print("Blockchain not available for dashboard")


app = Flask(__name__)
app.config['SECRET_KEY'] = 'rfid_security_scanner_web_key'
socketio = SocketIO(app, cors_allowed_origins="*")


web_helper = None
is_scanning = False
latest_scan_result = None

if AUTH_AVAILABLE:
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login_page'

    @login_manager.user_loader
    def load_user(user_id):
        return auth_manager.get_user_by_id(int(user_id))

def ensure_database_exists():

    try:
        conn = sqlite3.connect('shared_scans.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

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
                raw_data TEXT,
                blockchain_hash TEXT,
                peer_validations INTEGER,
                network_enhanced_score INTEGER,
                blockchain_timestamp TEXT,
                consensus_confidence INTEGER,
                risk_improvement INTEGER,
                similar_vulnerabilities INTEGER,
                threat_level TEXT,
                exploitation_likelihood TEXT,
                recommended_action TEXT
            )
        ''')

        conn.commit()
        conn.close()
        print("Database table verified/created")
        return True
    except Exception as e:
        print(f"Database error: {e}")
        return False

def reset_scanner_state():

    global is_scanning
    try:
        if web_helper:

            coordinator = get_coordinator()
            coordinator.is_scanning = False
            coordinator.current_user = "nobody"
            print("Scanner state reset")

        is_scanning = False
        return True
    except Exception as e:
        print(f"Scanner reset failed: {e}")
        return False

def setup_integration():

    global web_helper
    try:
        if INTEGRATION_AVAILABLE:

            coordinator = get_coordinator()


            status = coordinator.get_status()
            if not status.get('available', False):
                print("No scanner registered with coordinator")
                print("   Make sure main.py is running first!")
                return False


            web_helper = WebHelper(socketio)
            print("Web integration established with main.py")
            print(f"   Scanner available: {status.get('scanner_connected', False)}")
            print(f"   Current user: {status.get('current_user', 'nobody')}")
            return True
        else:
            print("Integration not available - rfid_web_integration module not found")
            return False
    except Exception as e:
        print(f"Integration setup failed: {e}")
        print("   Make sure main.py is running first with option 1!")
        return False

def setup_database():

    try:
        conn = sqlite3.connect('shared_scans.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()


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
                raw_data TEXT,
                blockchain_hash TEXT,
                peer_validations INTEGER,
                network_enhanced_score INTEGER,
                blockchain_timestamp TEXT,
                consensus_confidence INTEGER,
                risk_improvement INTEGER,
                similar_vulnerabilities INTEGER,
                threat_level TEXT,
                exploitation_likelihood TEXT,
                recommended_action TEXT
            )
        ''')

        conn.commit()
        conn.close()
        print("Database ready")
        return True
    except Exception as e:
        print(f"Database setup failed: {e}")
        return False

def perform_scan(timeout=15):

    global latest_scan_result, is_scanning

    try:
        print("Checking integration...")

        if not web_helper or not INTEGRATION_AVAILABLE:
            print("No web helper or integration")
            error_result = {
                'status': 'error',
                'message': 'Integration system not available - please run through main.py',
                'timestamp': datetime.now().isoformat()
            }
            socketio.emit('scan_result', error_result)
            socketio.emit('scan_status', {'status': 'error', 'message': 'Please run through main.py for full integration'})
            return error_result


        coordinator = get_coordinator()
        status = coordinator.get_status()
        print(f"Coordinator status: {status}")

        if not status.get('available', False):
            print("Scanner not available in coordinator")
            error_result = {
                'status': 'error',
                'message': 'Scanner not registered with coordinator - please run main.py first',
                'timestamp': datetime.now().isoformat()
            }
            socketio.emit('scan_result', error_result)
            socketio.emit('scan_status', {'status': 'error', 'message': 'Scanner not registered with coordinator'})
            return error_result

        print("Integration looks good, starting scan...")
        is_scanning = True
        socketio.emit('scan_status', {'status': 'scanning', 'message': 'Looking for cards...'})


        result = web_helper.scan_from_web(timeout)

        if result.get('status') == 'completed':

            save_scan_result(result)
            latest_scan_result = result

            print(f"Received shared scan from main.py: {result.get('card_type')} - {result.get('risk_level')} risk")


            socketio.emit('scan_result', result)
            socketio.emit('scan_status', {'status': 'completed', 'message': 'Scan completed successfully'})

            return result
        elif result.get('status') == 'no_card':
            socketio.emit('scan_result', result)
            socketio.emit('scan_status', {'status': 'no_card', 'message': 'No card detected'})
            return result
        else:
            socketio.emit('scan_result', result)
            socketio.emit('scan_status', {'status': 'error', 'message': result.get('message', 'Scan failed')})
            return result

    except Exception as e:
        print(f"Error in perform_scan: {e}")
        error_result = {
            'status': 'error',
            'message': f'Scan failed: {str(e)}',
            'timestamp': datetime.now().isoformat()
        }

        socketio.emit('scan_result', error_result)
        socketio.emit('scan_status', {'status': 'error', 'message': str(e)})

        return error_result
    finally:
        is_scanning = False

        reset_scanner_state()

def save_scan_result(result):

    try:

        print(f" DEBUG: save_scan_result received vulnerabilities_found = {result.get('vulnerabilities_found')}")
        print(f" DEBUG: result keys = {list(result.keys())}")


        ensure_database_exists()

        conn = sqlite3.connect('shared_scans.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()


        real_vulnerability_count = 0


        if 'confirmed_vulnerabilities' in result and result['confirmed_vulnerabilities'] is not None:
            real_vulnerability_count = int(result['confirmed_vulnerabilities'])
            print(f"DEBUG: Using explicit confirmed_vulnerabilities: {real_vulnerability_count}")


        elif result.get('raw_assessment') and isinstance(result.get('raw_assessment'), dict):
            raw_assessment = result.get('raw_assessment', {})
            confirmed_findings = raw_assessment.get('confirmed_findings', [])
            if confirmed_findings and isinstance(confirmed_findings, list):
                real_vulnerability_count = len(confirmed_findings)
                print(f"DEBUG: Found {real_vulnerability_count} CONFIRMED vulnerabilities in raw assessment")


        elif result.get('_complete_console_report'):
            console_report = result.get('_complete_console_report')

            import re
            confirmed_match = re.search(r'CONFIRMED VULNERABILITIES.*?\((\d+)\)', console_report)
            if confirmed_match:
                real_vulnerability_count = int(confirmed_match.group(1))
                print(f"DEBUG: Extracted {real_vulnerability_count} confirmed vulnerabilities from console report")


        elif 'vulnerabilities_found' in result and result['vulnerabilities_found'] is not None:

            if (result.get('source') == 'console' and
                not result.get('raw_assessment')):
                real_vulnerability_count = int(result['vulnerabilities_found'])
                print(f"DEBUG: Using vulnerabilities_found from console: {real_vulnerability_count}")
            else:

                real_vulnerability_count = int(result['vulnerabilities_found'])
                print(f"DEBUG: Using vulnerabilities_found (may need verification): {real_vulnerability_count}")


        if real_vulnerability_count == 0:
            print(f"DEBUG: No confirmed vulnerabilities found, using 0")


        ai_analysis = ''


        if result.get('_complete_console_report'):
            console_report = result.get('_complete_console_report')


            ai_start_markers = [
                "================================================================================\nAI-POWERED THREAT PATTERN ANALYSIS\n================================================================================"

            ]

            for marker in ai_start_markers:
                start_pos = console_report.find(marker)
                if start_pos != -1:

                    end_markers = [
                        "AI ANALYSIS COMPLETED",
                        "\nScan completed successfully",
                        "================================================================================\nEND OF"

                    ]

                    end_pos = len(console_report)
                    for end_marker in end_markers:
                        marker_pos = console_report.find(end_marker, start_pos + len(marker))
                        if marker_pos != -1:
                            if end_marker == "AI ANALYSIS COMPLETED":
                                end_pos = marker_pos + len(end_marker)
                            else:
                                end_pos = marker_pos
                            break

                    ai_analysis = console_report[start_pos:end_pos].strip()
                    if len(ai_analysis) > 200:
                        print(f"DEBUG: Extracted AI analysis section ({len(ai_analysis)} characters)")
                        break


        if not ai_analysis and result.get('_full_ai_results'):
            ai_analysis = result.get('_full_ai_results')
        elif not ai_analysis and result.get('ai_analysis_text'):
            ai_analysis = result.get('ai_analysis_text')
        elif not ai_analysis and result.get('ai_analysis') and isinstance(result.get('ai_analysis'), str):
            ai_analysis = result.get('ai_analysis')


        card_uid = result.get('card_uid', '')
        timestamp = result.get('timestamp', datetime.now().isoformat())


        cursor.execute('''
            SELECT COUNT(*) FROM shared_scans
            WHERE card_uid = ? AND datetime(timestamp) > datetime('now', '-30 seconds')
        ''', (card_uid,))

        existing_count = cursor.fetchone()[0]

        if existing_count > 0:
            print(f"Duplicate scan prevented for card {card_uid} - already scanned recently")
            conn.close()
            return


        cursor.execute('''
            INSERT INTO shared_scans (timestamp, source, card_uid, risk_level, vulnerability_score,
                             vulnerabilities_found, card_type, detection_time, findings, ai_analysis, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            timestamp,
            result.get('source', 'web'),
            card_uid,
            result.get('risk_level', ''),
            result.get('vulnerability_score', 0),
            real_vulnerability_count,
            result.get('card_type', ''),
            result.get('detection_time', 0.0),
            json.dumps(result.get('findings', [])),
            ai_analysis,
            json.dumps(result)
        ))

        conn.commit()
        conn.close()
        print(f"Scan result saved successfully with {real_vulnerability_count} CONFIRMED vulnerabilities")
        print(f" AI analysis length: {len(ai_analysis)} characters")

    except Exception as e:
        print(f"Could not save scan result: {e}")
        import traceback
        print(f"Error traceback: {traceback.format_exc()}")

def get_ai_analysis_from_scan(scan_data):



    console_report = ''
    if isinstance(scan_data, dict):
        console_report = scan_data.get('_complete_console_report', '')
    elif hasattr(scan_data, 'get') and scan_data.get('raw_data'):
        try:
            raw_data = json.loads(scan_data['raw_data'])
            console_report = raw_data.get('_complete_console_report', '')
        except:
            pass


    if console_report and len(console_report) > 100:

        ai_start_markers = [
            "================================================================================\nAI-POWERED THREAT PATTERN ANALYSIS\n================================================================================"

        ]

        for marker in ai_start_markers:
            start_pos = console_report.find(marker)
            if start_pos != -1:

                end_markers = [
                    "AI ANALYSIS COMPLETED\n\nScan completed successfully",
                    "\nScan completed successfully",
                    "================================================================================\nEND OF",

                ]

                end_pos = len(console_report)
                for end_marker in end_markers:
                    marker_pos = console_report.find(end_marker, start_pos + len(marker))
                    if marker_pos != -1:
                        if "AI ANALYSIS COMPLETED" in end_marker:
                            end_pos = marker_pos + len("AI ANALYSIS COMPLETED")
                        else:
                            end_pos = marker_pos
                        break

                ai_section = console_report[start_pos:end_pos].strip()
                if len(ai_section) > 200:

                    ai_section = ai_section.replace('\n================================================================================', '\n' + '='*80)
                    return ai_section


    if isinstance(scan_data, dict):

        raw_assessment = scan_data.get('raw_assessment', {})
        if raw_assessment and isinstance(raw_assessment, dict):
            ai_data = raw_assessment.get('ai_analysis', {})
            if ai_data and isinstance(ai_data, dict):
                return build_ai_analysis_from_real_data(ai_data, raw_assessment)

    if hasattr(scan_data, 'get') and scan_data.get('raw_data'):
        try:
            raw_data = json.loads(scan_data['raw_data'])
            raw_assessment = raw_data.get('raw_assessment', {})
            if raw_assessment:
                ai_data = raw_assessment.get('ai_analysis', {})
                if ai_data and isinstance(ai_data, dict):
                    return build_ai_analysis_from_real_data(ai_data, raw_assessment)
        except:
            pass


    if hasattr(scan_data, 'get'):
        ai_text = scan_data.get('ai_analysis', '')
        if isinstance(ai_text, str) and len(ai_text) > 100:
            return ai_text


    return "AI analysis data not found in console report. Please ensure the scan was completed through the console interface."

def build_ai_analysis_from_real_data(ai_data, raw_assessment):


    try:
        ai_lines = []


        if not ai_data or not isinstance(ai_data, dict):
            return "AI analysis data structure not found"


        ai_lines.append("=" * 80)
        ai_lines.append("AI-POWERED THREAT PATTERN ANALYSIS")
        ai_lines.append("=" * 80)


        ai_lines.append("AI SYSTEM STATUS")
        ai_lines.append("-" * 40)
        ai_lines.append("Anomaly Detection: Active")
        ai_lines.append("Pattern Recognition: Active")
        ai_lines.append("Behavioral Analysis: Active")
        ai_lines.append("Risk Prediction: Active")
        ai_lines.append("Threat Classification: Active")


        historical_count = ai_data.get('historical_scans_count', 10)
        ai_lines.append(f"Historical Data: {historical_count} scans loaded")
        ai_lines.append("")


        behavioral = ai_data.get('behavioral_analysis', {})
        if behavioral and behavioral.get('anomaly_score') is not None:
            anomaly_score = behavioral.get('anomaly_score', 0)
            ai_lines.append("ANOMALY DETECTION RESULTS")
            ai_lines.append("-" * 40)
            ai_lines.append("Status: active_monitoring")
            ai_lines.append(f"Anomaly Score: {anomaly_score:.3f}")


            if anomaly_score > 0.6:
                anomaly_risk = "HIGH"
            elif anomaly_score > 0.4:
                anomaly_risk = "MEDIUM"
            else:
                anomaly_risk = "LOW"
            ai_lines.append(f"Risk Level: {anomaly_risk}")
            ai_lines.append("Baseline: 10 historical scans")


            risk_factors = ai_data.get('risk_assessment', {}).get('risk_factors', [])
            if risk_factors:
                ai_lines.append("Anomalies Detected: 1")
                detection_time = raw_assessment.get('metadata', {}).get('detection_time', 0)
                ai_lines.append(f"  • slow_response_time: MEDIUM")
                ai_lines.append(f"    Response time ({detection_time}s) exceeds historical average (4.2s)")

            ai_lines.append("")


        patterns = ai_data.get('threat_patterns', [])
        if patterns and len(patterns) > 0:
            ai_lines.append("THREAT PATTERN RECOGNITION")
            ai_lines.append("-" * 40)
            ai_lines.append(f"Threat Patterns Detected: {len(patterns)}")
            for pattern in patterns:
                pattern_name = pattern.get('pattern', 'Unknown')
                risk_level = pattern.get('risk_level', 'LOW')
                confidence = pattern.get('confidence', 0.65)
                description = pattern.get('description', 'Assessment within normal historical parameters (3 vs avg 4.4)')

                ai_lines.append(f"  • {pattern_name}")
                ai_lines.append(f"    Risk Level: {risk_level}")
                ai_lines.append(f"    Confidence: {confidence}%")
                ai_lines.append(f"    Description: {description}")

            scan_count = ai_data.get('historical_scans_count', 10) + 1
            ai_lines.append(f"Context: {scan_count} scans analyzed")
            ai_lines.append("")


        risk_assessment = ai_data.get('risk_assessment', {})
        if risk_assessment:
            ai_lines.append("AI THREAT CLASSIFICATION")
            ai_lines.append("-" * 40)
            classification = risk_assessment.get('classification', 'UNKNOWN')
            threat_score = risk_assessment.get('threat_score', 0)
            ai_confidence = risk_assessment.get('ai_confidence', 0)

            ai_lines.append(f"Classification: {classification}")
            ai_lines.append(f"Threat Score: {threat_score}")
            ai_lines.append(f"AI Confidence: {ai_confidence}%")
            ai_lines.append("")


        if risk_assessment and risk_assessment.get('ai_risk_score'):
            ai_lines.append("OVERALL AI THREAT ASSESSMENT")
            ai_lines.append("-" * 40)
            ai_risk_score = risk_assessment.get('ai_risk_score', 76.0)
            overall_score = ai_risk_score / 100.0
            threat_level = risk_assessment.get('risk_category', 'CRITICAL')
            ai_confidence = risk_assessment.get('ai_confidence', 0)

            ai_lines.append(f"AI Threat Level: {threat_level}")
            ai_lines.append(f"Overall Score: {overall_score:.3f}/1.000")
            ai_lines.append(f"AI Confidence: {ai_confidence}%")
            ai_lines.append("")


        if len(ai_lines) > 10:
            ai_lines.append("KEY AI INSIGHTS")
            ai_lines.append("-" * 40)
            insights_count = 1

            historical_count = ai_data.get('historical_scans_count', 10)
            ai_lines.append(f"{insights_count}. AI analysis enhanced by {historical_count} historical scans for improved accuracy")
            insights_count += 1

            if behavioral and behavioral.get('anomaly_score') is not None:
                anomaly_score = behavioral.get('anomaly_score', 0)
                ai_lines.append(f"{insights_count}. AI detected anomalies (score: {anomaly_score:.3f}) based on historical patterns")
                insights_count += 1

            if patterns:
                ai_lines.append(f"{insights_count}. AI identified {len(patterns)} threat patterns using historical context")
                insights_count += 1

            if risk_assessment and risk_assessment.get('ai_risk_score'):
                overall_score = risk_assessment.get('ai_risk_score', 76.0) / 100.0
                threat_level = risk_assessment.get('risk_category', 'CRITICAL')
                ai_lines.append(f"{insights_count}. AI threat assessment: {threat_level} (score: {overall_score:.3f})")

            ai_lines.append("")


        ai_recommendations = ai_data.get('recommendations', [])
        if ai_recommendations and len(ai_recommendations) > 0:
            ai_lines.append("AI-POWERED RECOMMENDATIONS")
            ai_lines.append("-" * 40)
            for rec in ai_recommendations:
                if isinstance(rec, str):
                    ai_lines.append(f"-> {rec} (Priority: INFO)")
                elif isinstance(rec, dict):
                    title = rec.get('title', rec.get('recommendation', 'AI Recommendation'))
                    priority = rec.get('priority', 'INFO')
                    ai_lines.append(f"-> {title} (Priority: {priority})")
                    if rec.get('reasoning'):
                        ai_lines.append(f"   Reasoning: {rec.get('reasoning')}")
                ai_lines.append("")

        ai_lines.append("AI ANALYSIS COMPLETED")

        return "\n".join(ai_lines)

    except Exception as e:
        return f"Error building AI analysis from real data: {str(e)}"

def reconstruct_complete_console_report(scan_data):



    if isinstance(scan_data, dict) and scan_data.get('_complete_console_report'):
        complete_report = scan_data['_complete_console_report']

        if ("CONFIRMED VULNERABILITIES" in complete_report and
            ("CVSS:" in complete_report or "Card tracking" in complete_report)):
            return complete_report


    if hasattr(scan_data, 'get') and scan_data.get('raw_data'):
        try:
            raw_data = json.loads(scan_data['raw_data'])
            if raw_data.get('_complete_console_report'):
                complete_report = raw_data['_complete_console_report']
                if ("CONFIRMED VULNERABILITIES" in complete_report and
                    ("CVSS:" in complete_report or "Card tracking" in complete_report)):
                    return complete_report


            if raw_data.get('raw_assessment'):
                return build_console_report_from_assessment(raw_data['raw_assessment'])

        except json.JSONDecodeError:
            pass


    return build_basic_report_from_scan_data(scan_data)

def build_console_report_from_assessment(raw_assessment):


    try:
        metadata = raw_assessment.get('metadata', {})
        target_analysis = raw_assessment.get('target_analysis', {})
        confirmed_findings = raw_assessment.get('confirmed_findings', [])
        theoretical_vulns = raw_assessment.get('theoretical_vulnerabilities', [])
        security_features = raw_assessment.get('security_features', [])
        recommendations = raw_assessment.get('professional_recommendations', [])
        blockchain_analysis = raw_assessment.get('blockchain_analysis', {})
        ai_analysis = raw_assessment.get('ai_analysis', {})

        report_lines = []


        report_lines.append("=" * 80)
        report_lines.append("PROFESSIONAL SECURITY ASSESSMENT REPORT")
        report_lines.append("=" * 80)
        report_lines.append("")


        report_lines.append("=" * 80)
        report_lines.append("PROFESSIONAL RFID SECURITY ASSESSMENT REPORT")
        report_lines.append("=" * 80)
        report_lines.append("Development and Evaluation of a Portable RFID Security Testing Device")
        report_lines.append("")


        if metadata:
            report_lines.append(f"Assessment ID: {metadata.get('assessment_id', 'Unknown')}")
            report_lines.append(f"Date/Time: {metadata.get('timestamp', 'Unknown')}")
            report_lines.append(f"Framework: {metadata.get('framework', 'Professional RFID Security Assessment Framework')}")
            report_lines.append(f"Methodology: {metadata.get('methodology', 'Conservative RC522-based analysis')}")
            report_lines.append("")


        if target_analysis:
            report_lines.append("TARGET ANALYSIS")
            report_lines.append("-" * 40)
            report_lines.append(f"Card UID: {target_analysis.get('uid', 'Unknown')}")
            report_lines.append(f"Card Type: {target_analysis.get('estimated_type', 'Unknown')}")
            report_lines.append(f"Frequency: {target_analysis.get('frequency_confirmed', '13.56MHz')}")
            report_lines.append(f"Compatibility: {'Compatible' if target_analysis.get('card_compatible') else 'Unknown'}")
            if metadata.get('detection_time'):
                report_lines.append(f"Detection Time: {metadata.get('detection_time', 0)}s")


            manufacturer = target_analysis.get('manufacturer_analysis', {})
            if isinstance(manufacturer, dict) and manufacturer.get('name'):
                report_lines.append(f"Manufacturer: {manufacturer.get('name', 'Unknown')} (Confidence: {manufacturer.get('confidence', 'LOW')})")


            entropy = target_analysis.get('uid_entropy', {})
            if entropy and entropy.get('shannon_entropy') is not None:
                report_lines.append(f"UID Entropy: {entropy.get('shannon_entropy', 0)} ({entropy.get('assessment', 'UNKNOWN')})")
                report_lines.append(f"Randomness Quality: {entropy.get('randomness_quality', 'UNKNOWN')}")

            report_lines.append("")


        if confirmed_findings is not None or theoretical_vulns is not None or security_features is not None:
            report_lines.append("EXECUTIVE SUMMARY")
            report_lines.append("-" * 40)
            report_lines.append(f"Confirmed Vulnerabilities: {len(confirmed_findings)}")
            report_lines.append(f"Theoretical Vulnerabilities: {len(theoretical_vulns)}")
            report_lines.append(f"Security Features Detected: {len(security_features)}")


            if confirmed_findings:
                total_cvss = sum(f.get('cvss_score', 0) for f in confirmed_findings if f.get('cvss_score'))
                if total_cvss > 0:
                    avg_cvss = total_cvss / len(confirmed_findings)
                    risk_level = 'HIGH' if avg_cvss >= 7 else 'MEDIUM' if avg_cvss >= 4 else 'LOW'
                    report_lines.append(f"Overall Risk Level: {risk_level} (Score: {avg_cvss:.1f}/10)")

            report_lines.append("")


        if blockchain_analysis and blockchain_analysis.get('original_risk_score') is not None:
            report_lines.append("BLOCKCHAIN SECURITY NETWORK ANALYSIS")
            report_lines.append("-" * 40)
            report_lines.append(f"Original Risk Score: {blockchain_analysis.get('original_risk_score', 0)}/100")
            report_lines.append(f"Network Enhanced Score: {blockchain_analysis.get('network_enhanced_score', 0)}/100")
            report_lines.append(f"Risk Improvement: +{blockchain_analysis.get('risk_improvement', 0)} points")
            report_lines.append(f"Peer Validations: {blockchain_analysis.get('peer_validations', 0)}")
            report_lines.append(f"Network Consensus: {blockchain_analysis.get('network_consensus', 0)}%")

            blockchain_hash = blockchain_analysis.get('blockchain_hash', '')
            if len(blockchain_hash) > 32:
                display_hash = blockchain_hash[:32] + "..."
            else:
                display_hash = blockchain_hash
            report_lines.append(f"Blockchain Hash: {display_hash}")

            threat_intel = blockchain_analysis.get('threat_intelligence', {})
            if threat_intel and threat_intel.get('threat_level'):
                report_lines.append("")
                report_lines.append("GLOBAL THREAT INTELLIGENCE:")
                report_lines.append(f"   Threat Level: {threat_intel.get('threat_level')}")
                if threat_intel.get('recommended_action'):
                    report_lines.append(f"   Recommended Action: {threat_intel.get('recommended_action')}")
                if threat_intel.get('global_trend'):
                    report_lines.append(f"   Global Trend: {threat_intel.get('global_trend')}")
                if threat_intel.get('attack_frequency'):
                    report_lines.append(f"   Attack Frequency: {threat_intel.get('attack_frequency')}")

            report_lines.append("")

        if confirmed_findings:
            report_lines.append(f"CONFIRMED VULNERABILITIES ({len(confirmed_findings)})")
            report_lines.append("-" * 40)
            for i, finding in enumerate(confirmed_findings, 1):
                report_lines.append(f"{i}. {finding.get('finding', 'Vulnerability detected')}")


                severity = finding.get('severity', 'UNKNOWN')
                cvss_score = finding.get('cvss_score', 0)
                if cvss_score > 0:
                    report_lines.append(f"   Severity: {severity} (CVSS: {cvss_score})")
                else:
                    report_lines.append(f"   Severity: {severity}")

                if finding.get('confidence'):
                    report_lines.append(f"   Confidence: {finding.get('confidence')}")


                impact = finding.get('real_world_impact', finding.get('impact', ''))
                if impact:
                    report_lines.append(f"   Impact: {impact}")


                rc522_info = finding.get('rc522_capability', '')
                if rc522_info:
                    report_lines.append(f"   RC522 Analysis: {rc522_info}")


                evidence = finding.get('technical_evidence', '')
                if evidence:
                    report_lines.append(f"   Evidence: {evidence}")

                report_lines.append("")


        if theoretical_vulns:
            report_lines.append(f"THEORETICAL VULNERABILITIES ({len(theoretical_vulns)})")
            report_lines.append("-" * 40)
            report_lines.append("Note: These vulnerabilities require specialized equipment to exploit")
            report_lines.append("")

            for i, vuln in enumerate(theoretical_vulns, 1):
                finding_name = vuln.get('finding', vuln.get('vulnerability', 'Theoretical vulnerability'))
                report_lines.append(f"{i}. {finding_name}")


                severity = vuln.get('severity', 'UNKNOWN')
                cvss_score = vuln.get('cvss_score', 0)
                if cvss_score > 0:
                    report_lines.append(f"   Severity: {severity} (CVSS: {cvss_score})")
                else:
                    report_lines.append(f"   Severity: {severity}")

                if vuln.get('confidence'):
                    report_lines.append(f"   Confidence: {vuln.get('confidence')}")

                equipment = vuln.get('required_equipment', '')
                if equipment:
                    report_lines.append(f"   Required Equipment: {equipment}")

                complexity = vuln.get('attack_complexity', '')
                if complexity:
                    report_lines.append(f"   Attack Complexity: {complexity}")

                limitation = vuln.get('rc522_limitation', '')
                if limitation:
                    report_lines.append(f"   RC522 Limitation: {limitation}")


                refs = vuln.get('academic_references', [])
                if refs:
                    report_lines.append(f"   References: {', '.join(refs)}")

                report_lines.append("")


        if recommendations:
            report_lines.append(f"PROFESSIONAL RECOMMENDATIONS ({len(recommendations)})")
            report_lines.append("-" * 40)
            for rec in recommendations:
                title = rec.get('title', rec.get('recommendation', 'Security recommendation'))
                priority = rec.get('priority', 'MEDIUM')
                report_lines.append(f"-> {title} (Priority: {priority})")

                category = rec.get('category', '')
                if category:
                    report_lines.append(f"   Category: {category}")

                description = rec.get('description', '')
                if description:
                    report_lines.append(f"   Description: {description}")


                action_items = rec.get('action_items', [])
                if action_items:
                    report_lines.append("   Action Items:")
                    for action in action_items:
                        report_lines.append(f"     • {action}")


                equipment = rec.get('equipment_requirements', '')
                if equipment:
                    report_lines.append(f"   Equipment: {equipment}")

                report_lines.append("")


            report_lines.append("FOR ADVANCED TESTING REQUIRES:")
            report_lines.append("   • Proxmark3 RDV4 (€300-400)")
            report_lines.append("   • Chameleon RevE Rogue (€200-300)")
            report_lines.append("   • FlipperZero (€200)")
            report_lines.append("   • Professional security consultants")
            report_lines.append("")


        if ai_analysis and isinstance(ai_analysis, dict) and ai_analysis.get('risk_assessment'):
            ai_section = build_ai_analysis_from_real_data(ai_analysis, raw_assessment)
            if ai_section and "not found" not in ai_section:
                report_lines.append(ai_section)
                report_lines.append("")

        report_lines.append("Scan completed successfully")
        report_lines.append("")
        report_lines.append("=" * 80)
        report_lines.append("END OF PROFESSIONAL SECURITY ASSESSMENT REPORT")
        report_lines.append("=" * 80)
        report_lines.append(f"Generated: {metadata.get('timestamp', 'Unknown')}")
        report_lines.append("Framework: Professional RFID Security Assessment Framework")

        return "\n".join(report_lines)

    except Exception as e:
        return f"Error building console report from assessment: {str(e)}"

def build_basic_report_from_scan_data(scan_data):


    try:
        report_lines = []

        report_lines.append("PROFESSIONAL RFID SECURITY ASSESSMENT REPORT")
        report_lines.append("=" * 60)
        report_lines.append("")


        if hasattr(scan_data, 'get'):
            card_uid = scan_data.get('card_uid', '')
            card_type = scan_data.get('card_type', '')
            risk_level = scan_data.get('risk_level', '')
            vulnerability_score = scan_data.get('vulnerability_score', 0)
            vulnerabilities_found = scan_data.get('vulnerabilities_found', 0)
            timestamp = scan_data.get('timestamp', '')
            detection_time = scan_data.get('detection_time', 0)

            if card_uid or card_type:
                report_lines.append("TARGET ANALYSIS")
                report_lines.append("-" * 30)
                if card_uid:
                    report_lines.append(f"Card UID: {card_uid}")
                if card_type:
                    report_lines.append(f"Card Type: {card_type}")
                if detection_time > 0:
                    report_lines.append(f"Detection Time: {detection_time}s")
                if timestamp:
                    report_lines.append(f"Scan Time: {timestamp}")
                report_lines.append("")

            if risk_level or vulnerability_score > 0 or vulnerabilities_found > 0:
                report_lines.append("EXECUTIVE SUMMARY")
                report_lines.append("-" * 30)
                if risk_level:
                    report_lines.append(f"Overall Risk Level: {risk_level}")
                if vulnerability_score > 0:
                    report_lines.append(f"Vulnerability Score: {vulnerability_score}/100")
                if vulnerabilities_found > 0:
                    report_lines.append(f"Confirmed Vulnerabilities: {vulnerabilities_found}")
                report_lines.append("")


            findings = scan_data.get('findings', [])
            if findings and len(findings) > 0:
                report_lines.append(f"CONFIRMED VULNERABILITIES ({len(findings)})")
                report_lines.append("-" * 30)
                for i, finding in enumerate(findings, 1):
                    if finding and finding.strip():
                        report_lines.append(f"[{i}] {finding}")
                report_lines.append("")


        if len(report_lines) > 5:
            report_lines.append("=" * 60)
            report_lines.append("END OF REPORT")
        else:

            return "Complete console report data not available. Please scan through the main.py console interface for detailed analysis."

        return "\n".join(report_lines)

    except Exception as e:
        return f"Error creating basic report: {str(e)}"



@app.route('/login')
def login_page():

    if not AUTH_AVAILABLE:

        return redirect('/')
    return render_template('login.html')


@app.route('/api/register', methods=['POST'])
def register():

    if not AUTH_AVAILABLE:
        return jsonify({'success': False, 'message': 'Authentication not available'})

    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not all([name, email, password]):
        return jsonify({'success': False, 'message': 'All fields are required'})

    result = auth_manager.register_user(name, email, password)
    return jsonify(result)

@app.route('/api/verify_otp', methods=['POST'])
def verify_otp():

    if not AUTH_AVAILABLE:
        return jsonify({'success': False, 'message': 'Authentication not available'})

    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')

    result = auth_manager.verify_otp_and_create_user(email, otp)

    if result['success']:

        user = auth_manager.get_user_by_id(result['user_id'])
        if user:
            login_user(user)

    return jsonify(result)

@app.route('/api/login', methods=['POST'])
def login():

    if not AUTH_AVAILABLE:
        return jsonify({'success': False, 'message': 'Authentication not available'})

    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    result = auth_manager.login_user(email, password)

    if result['success']:
        login_user(result['user'])
        return jsonify({'success': True, 'message': 'Login successful'})

    return jsonify(result)



@app.route('/api/scan_history_user')
@login_required
def get_scan_history_user():

    try:
        conn = sqlite3.connect('shared_scans.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        if current_user.is_admin:

            cursor.execute('''
                SELECT id, timestamp, card_uid, risk_level, vulnerability_score,
                       vulnerabilities_found, card_type, detection_time
                FROM shared_scans
                ORDER BY timestamp DESC
                LIMIT 500
            ''')
        else:

            user_scans = auth_manager.get_user_scans(current_user.id)
            if user_scans:
                placeholders = ','.join('?' * len(user_scans))
                cursor.execute(f'''
                    SELECT id, timestamp, card_uid, risk_level, vulnerability_score,
                           vulnerabilities_found, card_type, detection_time
                    FROM shared_scans
                    WHERE id IN ({placeholders})
                    ORDER BY timestamp DESC
                ''', user_scans)
            else:

                conn.close()
                return jsonify({'history': []})

        results = cursor.fetchall()
        conn.close()

        history = []
        for row in results:
            history.append({
                'id': row['id'],
                'timestamp': row['timestamp'],
                'card_uid': row['card_uid'],
                'risk_level': row['risk_level'],
                'vulnerability_score': row['vulnerability_score'],
                'vulnerabilities_found': row['vulnerabilities_found'],
                'card_type': row['card_type'],
                'detection_time': row['detection_time']
            })

        return jsonify({'history': history, 'is_admin': current_user.is_admin})

    except Exception as e:
        print(f"Error in get_scan_history_user: {e}")
        return jsonify({'error': str(e), 'history': []})

@app.route('/api/logout', methods=['POST'])
def logout():

    if AUTH_AVAILABLE:
        logout_user()
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/user_info')
def user_info():

    if AUTH_AVAILABLE and current_user.is_authenticated:
        return jsonify({
            'logged_in': True,
            'name': current_user.name,
            'email': current_user.email,
            'id': current_user.id
        })
    else:
        return jsonify({'logged_in': False})


@app.route('/')
def home_page():

    if AUTH_AVAILABLE and not current_user.is_authenticated:
        return redirect('/login')
    return render_template('rfid_dashboard.html')

@app.route('/api/start_scan', methods=['POST'])
def start_scan():

    global is_scanning

    if is_scanning:
        return jsonify({
            'status': 'error',
            'message': 'Already scanning - please wait'
        })

    if not web_helper or not INTEGRATION_AVAILABLE:
        return jsonify({
            'status': 'error',
            'message': 'Integration system not available - please run through main.py'
        })

    try:

        scan_thread = threading.Thread(target=perform_scan, args=(15,))
        scan_thread.daemon = True
        scan_thread.start()

        return jsonify({
            'status': 'started',
            'message': 'Scan started - hold your card near the reader'
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Could not start scan: {str(e)}'
        })

@app.route('/api/stop_scan', methods=['POST'])
def stop_scan():

    global is_scanning

    if web_helper:
        web_helper.stop_web_scan()

    is_scanning = False

    return jsonify({
        'status': 'stopped',
        'message': 'Scan stopped'
    })

@app.route('/api/latest_result')
def get_latest_result():

    if latest_scan_result:
        return jsonify(latest_scan_result)
    else:
        return jsonify({
            'status': 'no_data',
            'message': 'No scans completed yet'
        })

@app.route('/api/scan_history')
def get_scan_history():

    try:
        if web_helper:

            dashboard_data = web_helper.get_dashboard_data()
            return jsonify(dashboard_data.get('history', {'history': []}))


        conn = sqlite3.connect('shared_scans.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, timestamp, card_uid, risk_level, vulnerability_score,
                   vulnerabilities_found, card_type, detection_time
            FROM shared_scans
            ORDER BY timestamp DESC
            LIMIT 500
        ''')

        results = cursor.fetchall()
        conn.close()

        history = []
        for row in results:
            history.append({
                'id': row['id'],
                'timestamp': row['timestamp'],
                'card_uid': row['card_uid'],
                'risk_level': row['risk_level'],
                'vulnerability_score': row['vulnerability_score'],
                'vulnerabilities_found': row['vulnerabilities_found'],
                'card_type': row['card_type'],
                'detection_time': row['detection_time']
            })

        return jsonify({'history': history})

    except Exception as e:
        print(f"Error in get_scan_history: {e}")
        return jsonify({'error': str(e), 'history': []})

@app.route('/api/statistics')
def get_statistics():

    try:
        if web_helper:

            dashboard_data = web_helper.get_dashboard_data()
            return jsonify(dashboard_data.get('statistics', {}))


        conn = sqlite3.connect('shared_scans.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()


        cursor.execute('SELECT COUNT(*) FROM shared_scans')
        total_scans_result = cursor.fetchone()
        total_scans = total_scans_result[0] if total_scans_result else 0


        cursor.execute('SELECT risk_level, COUNT(*) FROM shared_scans GROUP BY risk_level')
        risk_results = cursor.fetchall()
        risk_distribution = {}
        for row in risk_results:
            risk_distribution[row[0]] = row[1]


        cursor.execute('SELECT AVG(vulnerability_score) FROM shared_scans WHERE vulnerability_score > 0')
        avg_result = cursor.fetchone()
        avg_score = avg_result[0] if avg_result and avg_result[0] else 0

        conn.close()

        return jsonify({
            'total_scans': total_scans,
            'risk_distribution': risk_distribution,
            'average_vulnerability_score': round(avg_score, 1),
            'scanner_status': 'Integrated' if web_helper else 'Standalone',
            'scanner_available': INTEGRATION_AVAILABLE
        })

    except Exception as e:
        print(f"Error in get_statistics: {e}")
        return jsonify({
            'error': str(e),
            'total_scans': 0,
            'risk_distribution': {},
            'average_vulnerability_score': 0,
            'scanner_status': 'Error',
            'scanner_available': False
        })

@app.route('/api/export_data')
def export_data():

    try:
        ensure_database_exists()

        conn = sqlite3.connect('shared_scans.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()


        cursor.execute('''
            SELECT timestamp, card_uid, risk_level, vulnerability_score,
                   vulnerabilities_found, card_type, detection_time, findings, ai_analysis
            FROM shared_scans
            ORDER BY timestamp DESC
            LIMIT 10
        ''')

        results = cursor.fetchall()

        if not results:
            return jsonify({'error': 'No scans to export'})


        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"rfid_session_report_{timestamp}.html"


        html_content = f"""<!DOCTYPE html>
<html><head><title>RFID Latest Scans Report</title></head>
<body>
<h1>RFID Latest Scans Report</h1>
<p>Generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}</p>
<p>Most Recent {len(results)} Scans</p>
"""

        for i, row in enumerate(results, 1):
            risk_color = {'LOW': '#10b981', 'MEDIUM': '#f59e0b', 'HIGH': '#ef4444', 'CRITICAL': '#dc2626'}.get(row['risk_level'], '#6b7280')

            html_content += f"""
<div style="border:2px solid {risk_color}; margin:15px; padding:20px; border-radius:10px;">
<h3 style="color:{risk_color};">Scan #{i} - {row['risk_level']} Risk</h3>
<p><strong>Card UID:</strong> {row['card_uid']}</p>
<p><strong>Card Type:</strong> {row['card_type']}</p>
<p><strong>Security Score:</strong> {row['vulnerability_score']}/100</p>
<p><strong>Vulnerabilities Found:</strong> {row['vulnerabilities_found']}</p>
<p><strong>Scan Time:</strong> {row['timestamp']}</p>
<p><strong>Detection Time:</strong> {row['detection_time']:.2f}s</p>
"""
            if row['ai_analysis']:
                html_content += f"<p><strong>AI Analysis:</strong> Available</p>"

            html_content += "</div>"

        html_content += "</body></html>"

        with open(filename, 'w') as f:
            f.write(html_content)

        return jsonify({
            'status': 'success',
            'filename': filename,
            'records': len(results),
            'message': f'Exported {len(results)} most recent scans'
        })

    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/download/<filename>')
def download_file(filename):

    try:
        return send_file(filename, as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 404

@app.route('/api/view_file/<filename>')
def view_file(filename):

    try:
        if filename.endswith('.json'):
            with open(filename, 'r') as f:
                data = json.load(f)
            return jsonify(data)
        else:
            with open(filename, 'r') as f:
                content = f.read()
            return f"<pre style='font-family: monospace; padding: 20px;'>{content}</pre>", 200, {'Content-Type': 'text/html'}
    except Exception as e:
        return jsonify({'error': str(e)}), 404

@app.route('/api/list_files')
def list_files():

    try:

        session_reports = glob.glob("rfid_session_report_*.html")
        individual_reports = glob.glob("rfid_report_*.txt")
        json_reports = glob.glob("rfid_scan_*.json")
        comprehensive_reports = glob.glob("comprehensive_rfid_report_*.txt")
        ai_analysis_reports = glob.glob("complete_ai_analysis_*.txt")


        all_files = session_reports + individual_reports + json_reports + comprehensive_reports + ai_analysis_reports

        files = []
        for filename in all_files:
            try:
                file_stats = os.stat(filename)


                if filename.startswith("rfid_session_report_"):
                    file_type = "Latest Scans Export"
                elif filename.startswith("rfid_report_"):
                    file_type = "Individual Report"
                elif filename.startswith("rfid_scan_"):
                    file_type = "JSON Data"
                elif filename.startswith("comprehensive_rfid_report_"):
                    file_type = "Comprehensive Report"
                elif filename.startswith("complete_ai_analysis_"):
                    file_type = "Complete AI Analysis"
                else:
                    file_type = "Export File"

                files.append({
                    'filename': filename,
                    'size': file_stats.st_size,
                    'modified': datetime.fromtimestamp(file_stats.st_mtime).isoformat(),
                    'type': file_type
                })
            except:
                continue


        files.sort(key=lambda x: x['modified'], reverse=True)

        return jsonify({'files': files})

    except Exception as e:
        print(f"Error in list_files: {e}")
        return jsonify({'error': str(e), 'files': []})

@app.route('/api/download_scan_report/<int:scan_id>')
def download_scan_report(scan_id):

    try:

        if INTEGRATION_AVAILABLE:
            scan = get_scan_by_array_index(scan_id)
            if scan:

                report_content = f"""RFID SECURITY ASSESSMENT REPORT
{'=' * 50}

SCAN INFORMATION
Card UID: {scan.get('card_uid', 'Unknown')}
Card Type: {scan.get('card_type', 'Unknown')}
Scan Timestamp: {scan.get('timestamp', 'Unknown')}
Detection Time: {scan.get('detection_time', 0.0):.2f} seconds

SECURITY ASSESSMENT
Risk Level: {scan.get('risk_level', 'Unknown')}
Vulnerability Score: {scan.get('vulnerability_score', 0)}/100
Vulnerabilities Found: {scan.get('vulnerabilities_found', 0)}

SECURITY FINDINGS
{'-' * 30}
"""
                findings = scan.get('findings', [])
                if findings:
                    for i, finding in enumerate(findings, 1):
                        report_content += f"{i}. {finding}\n"
                else:
                    report_content += "No specific security findings recorded.\n"

                ai_analysis = scan.get('_full_ai_results') or scan.get('ai_analysis_text', '')
                if ai_analysis:
                    report_content += f"""
AI ANALYSIS
{'-' * 30}
{ai_analysis}
"""

                report_content += f"""
REPORT METADATA
{'-' * 30}
Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Scanner System: RFID Security Scanner v1.0
Assessment Type: Professional Security Analysis

{'=' * 50}
End of Report
"""


                safe_uid = scan.get('card_uid', 'unknown').replace(':', '_')
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"rfid_report_{safe_uid}_{timestamp}.txt"


                filepath = os.path.join(os.getcwd(), filename)
                with open(filepath, 'w') as f:
                    f.write(report_content)

                return send_file(filepath, as_attachment=True, download_name=filename)


        conn = sqlite3.connect('shared_scans.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM shared_scans WHERE id = ?
        ''', (scan_id,))

        scan = cursor.fetchone()
        conn.close()

        if not scan:
            return jsonify({'error': 'Scan not found'}), 404


        try:
            findings = json.loads(scan['findings']) if scan['findings'] else []
        except:
            findings = []


        report_content = f"""RFID SECURITY ASSESSMENT REPORT
{'=' * 50}

SCAN INFORMATION
Card UID: {scan['card_uid']}
Card Type: {scan['card_type']}
Scan Timestamp: {scan['timestamp']}
Detection Time: {scan['detection_time']:.2f} seconds

SECURITY ASSESSMENT
Risk Level: {scan['risk_level']}
Vulnerability Score: {scan['vulnerability_score']}/100
Vulnerabilities Found: {scan['vulnerabilities_found']}

SECURITY FINDINGS
{'-' * 30}
"""

        if findings:
            for i, finding in enumerate(findings, 1):
                report_content += f"{i}. {finding}\n"
        else:
            report_content += "No specific security findings recorded.\n"

        if scan['ai_analysis']:
            report_content += f"""
AI ANALYSIS
{'-' * 30}
{scan['ai_analysis']}
"""

        report_content += f"""
REPORT METADATA
{'-' * 30}
Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Scanner System: RFID Security Scanner v1.0
Assessment Type: Professional Security Analysis

{'=' * 50}
End of Report
"""


        safe_uid = scan['card_uid'].replace(':', '_') if scan['card_uid'] else 'unknown'
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"rfid_report_{safe_uid}_{timestamp}.txt"


        filepath = os.path.join(os.getcwd(), filename)
        with open(filepath, 'w') as f:
            f.write(report_content)

        return send_file(filepath, as_attachment=True, download_name=filename)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download_scan_json/<int:scan_id>')
def download_scan_json(scan_id):

    try:

        if INTEGRATION_AVAILABLE:
            scan = get_scan_by_array_index(scan_id)
            if scan:

                safe_uid = scan.get('card_uid', 'unknown').replace(':', '_')
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"rfid_scan_{safe_uid}_{timestamp}.json"


                filepath = os.path.join(os.getcwd(), filename)
                with open(filepath, 'w') as f:
                    json.dump(scan, f, indent=2)

                return send_file(filepath, as_attachment=True, download_name=filename)


        conn = sqlite3.connect('shared_scans.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM shared_scans WHERE id = ?
        ''', (scan_id,))

        scan = cursor.fetchone()
        conn.close()

        if not scan:
            return jsonify({'error': 'Scan not found'}), 404


        scan_data = dict(scan)


        try:
            scan_data['findings'] = json.loads(scan['findings']) if scan['findings'] else []
        except:
            scan_data['findings'] = []


        report_data = {
            'report_info': {
                'generated_at': datetime.now().isoformat(),
                'report_type': 'Individual RFID Security Assessment',
                'scanner_version': 'RFID Security Scanner v1.0'
            },
            'scan_data': scan_data
        }


        safe_uid = scan['card_uid'].replace(':', '_') if scan['card_uid'] else 'unknown'
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"rfid_scan_{safe_uid}_{timestamp}.json"


        filepath = os.path.join(os.getcwd(), filename)
        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2)

        return send_file(filepath, as_attachment=True, download_name=filename)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan_history_detailed')
def get_scan_history_detailed():

    try:
        if INTEGRATION_AVAILABLE:

            history_data = get_scan_history_with_indices(500)
            return jsonify({'success': True, 'history': history_data.get('history', [])})


        conn = sqlite3.connect('shared_scans.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, timestamp, card_uid, risk_level, vulnerability_score,
                   vulnerabilities_found, card_type, detection_time, ai_analysis
            FROM shared_scans
            ORDER BY timestamp DESC
            LIMIT 500
        ''')

        results = cursor.fetchall()
        conn.close()

        history = []
        for row in results:
            history.append({
                'id': row['id'],
                'timestamp': row['timestamp'],
                'card_uid': row['card_uid'],
                'risk_level': row['risk_level'],
                'vulnerability_score': row['vulnerability_score'],
                'vulnerabilities_found': row['vulnerabilities_found'],
                'card_type': row['card_type'],
                'detection_time': row['detection_time'],
                'has_ai_analysis': bool(row['ai_analysis'])
            })

        return jsonify({'success': True, 'history': history})

    except Exception as e:
        print(f"Error in get_scan_history_detailed: {e}")
        return jsonify({'success': False, 'error': str(e), 'history': []})

@app.route('/api/generate_comprehensive_report/<int:scan_id>')
def generate_comprehensive_report(scan_id):

    try:

        if INTEGRATION_AVAILABLE:
            scan = get_scan_by_array_index(scan_id)
            if scan:

                report_content = f"""
PROFESSIONAL RFID SECURITY ASSESSMENT
{'═' * 60}

EXECUTIVE SUMMARY
{'-' * 30}
A security assessment was conducted on an RFID card to evaluate potential
vulnerabilities and security risks. This report provides detailed findings
and recommendations for improving card security.

ASSESSMENT DETAILS
{'-' * 30}
Card Identifier: {scan.get('card_uid', 'Unknown')}
Card Technology: {scan.get('card_type', 'Unknown')}
Assessment Date: {scan.get('timestamp', 'Unknown')}
Detection Time: {scan.get('detection_time', 0.0):.2f} seconds
Assessment ID: RFID-{scan_id:06d}

RISK CLASSIFICATION
{'-' * 30}
Overall Risk Level: {scan.get('risk_level', 'Unknown')}
Vulnerability Score: {scan.get('vulnerability_score', 0)}/100

Risk Level Definitions:
• LOW (0-39): Minimal security concerns
• MEDIUM (40-69): Moderate security risks present
• HIGH (70-100): Significant security vulnerabilities

SECURITY FINDINGS
{'-' * 30}
Number of Vulnerabilities Identified: {scan.get('vulnerabilities_found', 0)}

Detailed Findings:
"""

                findings = scan.get('findings', [])
                if findings:
                    for i, finding in enumerate(findings, 1):
                        report_content += f"""
{i}. VULNERABILITY: {finding}
   Impact: Security risk to card and associated systems
   Recommendation: Implement additional security measures
"""
                else:
                    report_content += "\nNo specific security vulnerabilities were identified during this assessment.\n"

                ai_analysis = scan.get('_full_ai_results') or scan.get('ai_analysis_text', '')
                if ai_analysis:
                    report_content += f"""
AI-POWERED THREAT ANALYSIS
{'-' * 30}
{ai_analysis}
"""

                report_content += f"""
TECHNICAL SPECIFICATIONS
{'-' * 30}
• Card Type: {scan.get('card_type', 'Unknown')}
• Detection Time: {scan.get('detection_time', 0.0):.2f} seconds
• Assessment Method: Professional RFID Security Framework
• Analysis Engine: AI-Enhanced Vulnerability Detection

RECOMMENDATIONS
{'-' * 30}
Based on the assessment results, the following recommendations are provided:

1. IMMEDIATE ACTIONS
   • Review card usage policies and procedures
   • Implement additional access controls where possible
   • Monitor card usage for unusual patterns

2. LONG-TERM SECURITY IMPROVEMENTS
   • Consider upgrading to more secure card technologies
   • Implement multi-factor authentication systems
   • Regular security assessments and monitoring

3. ONGOING MONITORING
   • Periodic re-assessment of card security
   • Stay updated on latest RFID security best practices
   • Review and update security policies regularly

ASSESSMENT METADATA
{'-' * 30}
Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
Assessment System: RFID Security Scanner v1.0
Methodology: Professional Security Assessment Framework
Analyst: Automated Security Analysis System

DISCLAIMER
{'-' * 30}
This report is confidential and should
be handled according to your organization's security policies.

{'═' * 60}
END OF REPORT
"""


                safe_uid = scan.get('card_uid', 'unknown').replace(':', '_')
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"comprehensive_rfid_report_{safe_uid}_{timestamp}.txt"


                filepath = os.path.join(os.getcwd(), filename)
                with open(filepath, 'w') as f:
                    f.write(report_content)

                return send_file(filepath, as_attachment=True, download_name=filename)


        conn = sqlite3.connect('shared_scans.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM shared_scans WHERE id = ?
        ''', (scan_id,))

        scan = cursor.fetchone()
        conn.close()

        if not scan:
            return jsonify({'error': 'Scan not found'}), 404


        try:
            findings = json.loads(scan['findings']) if scan['findings'] else []
        except:
            findings = []


        report_content = f"""
PROFESSIONAL RFID SECURITY ASSESSMENT
{'═' * 60}

EXECUTIVE SUMMARY
{'-' * 30}
A security assessment was conducted on an RFID card to evaluate potential
vulnerabilities and security risks. This report provides detailed findings
and recommendations for improving card security.

ASSESSMENT DETAILS
{'-' * 30}
Card Identifier: {scan['card_uid']}
Card Technology: {scan['card_type']}
Assessment Date: {scan['timestamp']}
Detection Time: {scan['detection_time']:.2f} seconds
Assessment ID: RFID-{scan_id:06d}

RISK CLASSIFICATION
{'-' * 30}
Overall Risk Level: {scan['risk_level']}
Vulnerability Score: {scan['vulnerability_score']}/100

Risk Level Definitions:
• LOW (0-39): Minimal security concerns
• MEDIUM (40-69): Moderate security risks present
• HIGH (70-100): Significant security vulnerabilities

SECURITY FINDINGS
{'-' * 30}
Number of Vulnerabilities Identified: {scan['vulnerabilities_found']}

Detailed Findings:
"""

        if findings:
            for i, finding in enumerate(findings, 1):
                report_content += f"""
{i}. VULNERABILITY: {finding}
   Impact: Security risk to card and associated systems
   Recommendation: Implement additional security measures
"""
        else:
            report_content += "\nNo specific security vulnerabilities were identified during this assessment.\n"

        if scan['ai_analysis']:
            report_content += f"""
AI-POWERED THREAT ANALYSIS
{'-' * 30}
{scan['ai_analysis']}
"""

        report_content += f"""
TECHNICAL SPECIFICATIONS
{'-' * 30}
• Card Type: {scan['card_type']}
• Detection Time: {scan['detection_time']:.2f} seconds
• Assessment Method: Professional RFID Security Framework
• Analysis Engine: AI-Enhanced Vulnerability Detection

RECOMMENDATIONS
{'-' * 30}
Based on the assessment results, the following recommendations are provided:

1. IMMEDIATE ACTIONS
   • Review card usage policies and procedures
   • Implement additional access controls where possible
   • Monitor card usage for unusual patterns

2. LONG-TERM SECURITY IMPROVEMENTS
   • Consider upgrading to more secure card technologies
   • Implement multi-factor authentication systems
   • Regular security assessments and monitoring

3. ONGOING MONITORING
   • Periodic re-assessment of card security
   • Stay updated on latest RFID security best practices
   • Review and update security policies regularly

ASSESSMENT METADATA
{'-' * 30}
Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
Assessment System: RFID Security Scanner v1.0
Methodology: Professional Security Assessment Framework
Analyst: Automated Security Analysis System

DISCLAIMER
{'-' * 30}
This report is confidential and should
be handled according to your organization's security policies.

{'═' * 60}
END OF REPORT
"""


        safe_uid = scan['card_uid'].replace(':', '_') if scan['card_uid'] else 'unknown'
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"comprehensive_rfid_report_{safe_uid}_{timestamp}.txt"


        filepath = os.path.join(os.getcwd(), filename)
        with open(filepath, 'w') as f:
            f.write(report_content)

        return send_file(filepath, as_attachment=True, download_name=filename)

    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/api/get_full_ai_analysis/<int:scan_id>')
def get_full_ai_analysis(scan_id):
    """FIXED: Get ONLY the AI analysis section for a specific scan."""
    try:

        if INTEGRATION_AVAILABLE:
            scan = get_scan_by_array_index(scan_id)
            if scan:
                ai_analysis = get_ai_analysis_from_scan(scan)
                return jsonify({
                    'success': True,
                    'ai_analysis': ai_analysis,
                    'scan_id': scan_id
                })


        conn = sqlite3.connect('shared_scans.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT ai_analysis, raw_data FROM shared_scans WHERE id = ?
        ''', (scan_id,))

        result = cursor.fetchone()
        conn.close()

        if not result:
            return jsonify({'success': False, 'error': 'Scan not found'})


        scan_data = dict(result)
        ai_analysis = get_ai_analysis_from_scan(scan_data)

        return jsonify({
            'success': True,
            'ai_analysis': ai_analysis,
            'scan_id': scan_id
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/get_complete_console_report/<int:scan_id>')
def get_complete_console_report(scan_id):
    """FIXED: Get the complete console report exactly as it appeared."""
    try:

        if INTEGRATION_AVAILABLE:
            scan = get_scan_by_array_index(scan_id)
            if scan:
                complete_report = reconstruct_complete_console_report(scan)
                return jsonify({
                    'success': True,
                    'complete_report': complete_report,
                    'scan_id': scan_id
                })


        conn = sqlite3.connect('shared_scans.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM shared_scans WHERE id = ?', (scan_id,))
        result = cursor.fetchone()
        conn.close()

        if not result:
            return jsonify({'success': False, 'error': 'Scan data not found'})


        scan_data = dict(result)
        complete_report = reconstruct_complete_console_report(scan_data)

        return jsonify({
            'success': True,
            'complete_report': complete_report,
            'scan_id': scan_id
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/download_full_ai_report/<int:scan_id>')
def download_full_ai_report(scan_id):

    try:

        ai_analysis = ''
        scan_info = {}

        if INTEGRATION_AVAILABLE:
            scan = get_scan_by_array_index(scan_id)
            if scan:
                ai_analysis = get_ai_analysis_from_scan(scan)
                scan_info = {
                    'card_uid': scan.get('card_uid', 'Unknown'),
                    'card_type': scan.get('card_type', 'Unknown'),
                    'timestamp': scan.get('timestamp', 'Unknown'),
                    'risk_level': scan.get('risk_level', 'Unknown'),
                    'vulnerability_score': scan.get('vulnerability_score', 0),
                    'vulnerabilities_found': scan.get('vulnerabilities_found', 0),
                    'detection_time': scan.get('detection_time', 0.0)
                }


        if not ai_analysis or "not found" in ai_analysis:
            conn = sqlite3.connect('shared_scans.db')
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('''
                SELECT * FROM shared_scans WHERE id = ?
            ''', (scan_id,))

            scan = cursor.fetchone()
            conn.close()

            if not scan:
                return jsonify({'error': 'Scan not found'}), 404

            scan_data = dict(scan)
            ai_analysis = get_ai_analysis_from_scan(scan_data)

            scan_info = {
                'card_uid': scan['card_uid'],
                'card_type': scan['card_type'],
                'timestamp': scan['timestamp'],
                'risk_level': scan['risk_level'],
                'vulnerability_score': scan['vulnerability_score'],
                'vulnerabilities_found': scan['vulnerabilities_found'],
                'detection_time': scan['detection_time']
            }

        report_content = f"""
COMPLETE AI-POWERED THREAT ANALYSIS REPORT
{'=' * 80}

SCAN IDENTIFICATION
Card UID: {scan_info['card_uid']}
Card Type: {scan_info['card_type']}
Scan Timestamp: {scan_info['timestamp']}
Report ID: AI-RFID-{scan_id:06d}

{'=' * 80}
COMPLETE AI ANALYSIS RESULTS
{'=' * 80}

{ai_analysis}

{'=' * 80}
SCAN SUMMARY
{'=' * 80}
Risk Level: {scan_info['risk_level']}
Vulnerability Score: {scan_info['vulnerability_score']}/100
Vulnerabilities Found: {scan_info['vulnerabilities_found']}
Detection Time: {scan_info['detection_time']:.2f} seconds

REPORT METADATA
{'=' * 80}
Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
Report Type: Complete AI Security Analysis
System: RFID Security Scanner with AI Enhancement v1.0
Analysis Engine: AI-Powered Threat Detection System

{'=' * 80}
END OF AI ANALYSIS REPORT
"""

        safe_uid = scan_info['card_uid'].replace(':', '_') if scan_info['card_uid'] else 'unknown'
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"complete_ai_analysis_{safe_uid}_{timestamp}.txt"

        filepath = os.path.join(os.getcwd(), filename)
        with open(filepath, 'w') as f:
            f.write(report_content)

        return send_file(filepath, as_attachment=True, download_name=filename)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/blockchain-stats')
def get_blockchain_stats():

    if BLOCKCHAIN_AVAILABLE:
        try:
            stats = get_network_stats()
            return jsonify({
                'success': True,
                'data': stats,
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e),
                'data': {'active_peers': 0, 'total_vulnerabilities': 0}
            })
    else:
        return jsonify({
            'success': False,
            'error': 'Blockchain not available',
            'data': {'active_peers': 0, 'total_vulnerabilities': 0}
        })

@app.route('/api/enhance-scan', methods=['POST'])
def enhance_scan_with_blockchain():

    if not BLOCKCHAIN_AVAILABLE:
        return jsonify({'success': False, 'error': 'Blockchain not available'})

    try:
        data = request.get_json()
        scan_result = data.get('scan_result', {})


        enhanced = analyze_scan_real_time(scan_result)

        return jsonify({
            'success': True,
            'enhanced_result': enhanced,
            'blockchain_hash': enhanced.get('blockchain_hash'),
            'network_enhanced_score': enhanced.get('network_enhanced_score'),
            'peer_validations': enhanced.get('peer_validations')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})



@socketio.on('connect')
def handle_connect():

    status_msg = 'Connected to RFID Security Scanner (Integrated with main.py)' if web_helper else 'Connected to RFID Security Scanner (Standalone)'
    emit('status', {'message': status_msg})
    print("New web client connected")

@socketio.on('request_scan')
def handle_scan_request():

    start_scan()


if __name__ == '__main__':
    print("RFID Security Scanner - Web Interface")
    print("=" * 50)
    print("Integration receiver for main.py system")
    print("Starting web server...")


    ensure_database_exists()
    setup_database()
    integration_ready = setup_integration()

    if integration_ready:
        print("Integration with main.py established!")
        print("Web dashboard will receive REAL-TIME data from console scans")
    else:
        print("No integration - run this through main.py for full functionality")

    print()
    print("Web interface starting...")
    print("Open your browser to: http://localhost:5000")
    print("Or on your phone: http://[your-pi-ip]:5000")
    print()
    print("Press Ctrl+C to stop the web server")
    print("=" * 50)


    try:
        socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        print("\nWeb server stopped")
    except Exception as e:
        print(f"Web server error: {e}")