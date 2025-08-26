import time
import sys
import threading
import subprocess
import os
import socket
from datetime import datetime

# To import the scanner
try:
    from rfid_scanner import ProfessionalRFIDSecurityFramework, print_realtime_results
    SCANNER_READY = True
except ImportError as e:
    print(f"Scanner not found: {e}")
    SCANNER_READY = False

# for importing the integration system
try:
    from rfid_web_integration import setup_integration, ConsoleHelper, get_coordinator
    INTEGRATION_READY = True
except ImportError as e:
    print(f"Integration not available: {e}")
    INTEGRATION_READY = False

class RFIDSecurityTester:


    def __init__(self):
        self.show_welcome()
        self.setup_system()

    def get_ip_address(self):

        try:

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            try:

                hostname = socket.gethostname()
                ip = socket.gethostbyname(hostname)
                return ip
            except:
                return "localhost"

    def show_welcome(self):
        """ to Show welcome message and system info."""
        print("RFID Security Scanner")
        print("=" * 50)
        print("Professional Card Security Testing Tool")
        print("Find security issues in RFID cards and access cards")
        print("=" * 50)
        print()
        print("What this tool can do:")
        print("• Test RFID cards for security vulnerabilities")
        print("• Analyze card types and encryption")
        print("• Generate detailed security reports")
        print("• AI-powered threat analysis")
        print("• Web dashboard for easy use")
        print()
        print("Compatible cards:")
        print("• Building access cards (MIFARE)")
        print("• Transit cards (most types)")
        print("• Student ID cards")
        print("• Hotel key cards")
        print("• Most 13.56MHz RFID cards")
        print()
        print("Hardware detected: Raspberry Pi")
        print("Setting up scanner...")
        print("=" * 50)

    def setup_system(self):
        """Set up the scanning system."""
        self.integration_helper = None
        self.running = True
        self.web_process = None
        self.flask_app = None
        self.socketio = None

        if not SCANNER_READY:
            print("ERROR: RFID scanner hardware not available")
            print("This system requires real RFID scanner hardware to function")
            print("Please check  scanner connection and try again")
            sys.exit(1)

        if INTEGRATION_READY:
            try:
                # Set up RFID scanner
                self.scanner = ProfessionalRFIDSecurityFramework()

                if not self.scanner.test_scanner_connection():
                    print("ERROR: Scanner hardware not responding")
                    print("Please check  RC522 connections and try again")
                    sys.exit(1)

                print("Scanner ready")

                # Set up AI analysis
                try:
                    from ai_threat_analyzer import integrate_ai_with_framework
                    ai_analyzer = integrate_ai_with_framework(self.scanner)
                    print("AI analysis ready")
                except:
                    ai_analyzer = None
                    print("AI analysis not available")

                # Set up integration between console and web
                if setup_integration(self.scanner, ai_analyzer):
                    print("Console and web integration ready")
                    self.integration_helper = ConsoleHelper(self)
                else:
                    print("Integration setup failed - using basic mode")

            except Exception as e:
                print(f"Setup failed: {e}")
                print("Please check your hardware connections and try again")
                sys.exit(1)

        else:
            # Basic scanner without integration
            try:
                self.scanner = ProfessionalRFIDSecurityFramework()

                if not self.scanner.test_scanner_connection():
                    print("ERROR: Scanner hardware not responding")
                    print("Please check your RC522 connections and try again")
                    sys.exit(1)

                print("Scanner ready (basic mode)")
            except Exception as e:
                print(f"Scanner setup failed: {e}")
                print("Please check your hardware connections and try again")
                sys.exit(1)

    def show_menu(self):
        """Show the main menu options."""
        print("\nChoose how you want to use the scanner:")
        print()
        print("1. Web Interface + Console (Recommended)")
        print("   • Easy web dashboard + console output")
        print("   • Best for demos and detailed analysis")
        print()
        print("2. Console Only")
        print("   • Terminal-based scanning")
        print("   • Good for technical users")
        print()
        print("3. Web Interface Only")
        print("   • Browser-based interface")
        print("   • Good for presentations")
        print()
        choice = input("Enter your choice (1-3): ").strip()
        return choice

    def start_web_dashboard(self):

        try:
            print("\nStarting web dashboard...")


            sys.path.append(os.path.join(os.path.dirname(__file__), 'web_dashboard'))

            try:
                from app import app, socketio, setup_integration as setup_web_integration


                if setup_web_integration():
                    print("Web integration connected to main.py coordinator")
                else:
                    print("Web integration failed")
                    return False

                self.flask_app = app
                self.socketio = socketio


                pi_ip = self.get_ip_address()

                print("Web dashboard started successfully")
                print(f"Open your browser to:")
                print(f"  • From this Pi: http://localhost:5000")
                print(f"  • From other devices: http://{pi_ip}:5000")
                print(f"  • From your phone: http://{pi_ip}:5000")
                print()
                print("The web dashboard is now running and accessible!")
                return True

            except ImportError as e:
                print(f"Could not import web dashboard: {e}")
                return False

        except Exception as e:
            print(f"Could not start web dashboard: {e}")
            return False

    def run_web_server(self):

        try:
            if self.socketio and self.flask_app:
                print("Starting Flask web server...")
                self.socketio.run(self.flask_app, host='0.0.0.0', port=5000, debug=False, use_reloader=False)
            else:
                print("Web server not properly initialized")
        except Exception as e:
            print(f"Web server error: {e}")

    def run_console_tests(self):

        print("\nConsole Scanner Active")
        print("Hold RFID cards near the reader to test ")
        print("Press Ctrl+C to stop")
        print("-" * 40)

        test_count = 0

        try:
            while self.running:
                if self.integration_helper and self.scanner:

                    print(f"\nTest #{test_count + 1}: Looking for cards...")

                    result = self.integration_helper.scan_from_console(timeout=15)


                    if isinstance(result, tuple):

                        status = result[0] if len(result) > 0 else "error"
                        message = result[1] if len(result) > 1 else "No message"
                        data = result[2] if len(result) > 2 else {}


                        result = {
                            'status': status,
                            'message': message,
                            'data': data
                        }
                    elif not isinstance(result, dict):

                        result = {
                            'status': 'error',
                            'message': str(result),
                            'data': {}
                        }

                    if result["status"] == "completed":
                        test_count += 1
                        print("Scan completed successfully")
                        time.sleep(2)
                    elif result["status"] == "no_card":
                        print("No card detected - try holding it closer")
                        time.sleep(1)
                    else:
                        print(f"Scan failed: {result.get('message', 'Unknown error')}")
                        time.sleep(1)

                elif self.scanner:

                    print(f"\nTest #{test_count + 1}: Looking for cards...")

                    result = self.scanner.perform_professional_assessment(timeout=15)
                    if result:
                        print_realtime_results(self.scanner, result)
                        test_count += 1
                        print("Scan completed")
                        time.sleep(2)
                    else:
                        print("No card detected")
                        time.sleep(1)

                else:

                    print("ERROR: No scanner hardware available")
                    print("Please check your scanner connection")
                    break

        except KeyboardInterrupt:
            print("\n\nConsole testing stopped")

    def run_web_only(self):
        """Run only in web dashboard."""
        if self.start_web_dashboard():
            print("\nWeb dashboard is running")
            print("Use browser to scan cards")

            try:
                print("\nPress Ctrl+C to stop the web server")
                self.run_web_server()
            except KeyboardInterrupt:
                print("\nStopping web dashboard...")
        else:
            print("Could not start web dashboard")

    def run_combined_mode(self):
        """Run both web dashboard and console"""
        if self.start_web_dashboard():
            print("\nStarting combined mode...")
            pi_ip = self.get_ip_address()
            print(f"Web dashboard: http://{pi_ip}:5000")
            print("Console scanner will also run below")
            print("Both interfaces will show the same data")


            web_thread = threading.Thread(target=self.run_web_server)
            web_thread.daemon = True
            web_thread.start()


            time.sleep(2)


            try:
                print("\nPress Ctrl+C to stop both systems")
                self.run_console_tests()
            except KeyboardInterrupt:
                print("\nStopping all systems...")
                self.running = False
        else:
            print("Could not start combined mode")

    def run(self):

        choice = self.show_menu()

        if choice == "1":
            self.run_combined_mode()
        elif choice == "2":
            self.run_console_tests()
        elif choice == "3":
            self.run_web_only()
        else:
            print("Invalid choice. Please run again and choose 1, 2, or 3.")
            return

        self.cleanup()

    def cleanup(self):

        print("\nShutting down scanner...")

        # Stop web dashboard
        if self.flask_app:
            print("Web dashboard stopped")


        if self.scanner:
            try:
                self.scanner.cleanup()
                print("Scanner cleaned up")
            except:
                pass


        if INTEGRATION_READY:
            try:
                from rfid_web_integration import cleanup
                cleanup()
                print("Integration cleaned up")
            except:
                pass

        print("Goodbye! Thanks for using RFID Security Scanner")

def main():

    try:
        tester = RFIDSecurityTester()
        tester.run()
    except KeyboardInterrupt:
        print("\nGoodbye!")
    except Exception as e:
        print(f"Unexpected error: {e}")
        print("Please check your setup and try again")

if __name__ == "__main__":
    main()