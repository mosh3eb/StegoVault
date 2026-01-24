"""
Main GUI window for StegoVault
"""

import sys
import os
import traceback
from pathlib import Path
from typing import Optional

try:
    from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                 QHBoxLayout, QPushButton, QLabel, QFileDialog,
                                 QTextEdit, QProgressBar, QGroupBox, QLineEdit,
                                 QCheckBox, QComboBox, QMessageBox, QTabWidget)
    from PyQt6.QtCore import Qt, QThread, pyqtSignal
    from PyQt6.QtGui import QIcon, QFont, QPixmap, QPalette, QColor, QAction
    PYQT6_AVAILABLE = True
except ImportError:
    PYQT6_AVAILABLE = False

# App metadata
APP_NAME = "StegoVault"
APP_VERSION = "1.00"
APP_TAGLINE = "Advanced Steganography Tool"

# Add parent directory to path
current_dir = Path(__file__).parent.parent.absolute()
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

# Set PYTHONPATH for imports
os.environ['PYTHONPATH'] = str(current_dir)

# Import engine (support both folder casings)
try:
    from StegoVault.core import StegoEngine
    from StegoVault.cli import CLIInterface
except ImportError:
    try:
        from stegovault.core import StegoEngine
        from stegovault.cli import CLIInterface
    except ImportError:
        # If both fail, we might be in a bundled app, try adding root to path
        if hasattr(sys, "_MEIPASS"):
            sys.path.insert(0, sys._MEIPASS)
        else:
            root = Path(__file__).resolve().parent.parent
            sys.path.insert(0, str(root))
        
        try:
            from StegoVault.core import StegoEngine
            from StegoVault.cli import CLIInterface
        except ImportError:
            from stegovault.core import StegoEngine
            from stegovault.cli import CLIInterface


class StegoWorker(QThread):
    """Worker thread for steganography operations"""
    
    finished = pyqtSignal(bool, str)
    progress = pyqtSignal(int)
    message = pyqtSignal(str)
    
    def __init__(self, operation: str, **kwargs):
        super().__init__()
        self.operation = operation
        self.kwargs = kwargs
    
    def run(self):
        """Run the steganography operation"""
        try:
            # Initialize engine with same settings as main window
            enable_robustness = self.kwargs.get('robustness', False) or self.kwargs.get('enable_robustness', False)
            enable_anti_steganalysis = self.kwargs.get('anti_steganalysis', False) or self.kwargs.get('enable_anti_steganalysis', False)
            engine = StegoEngine(
                enable_robustness=enable_robustness,
                enable_anti_steganalysis=enable_anti_steganalysis
            )
            
            if self.operation == 'embed':
                try:
                    # Verify file exists
                    input_file = self.kwargs['input_file']
                    if not os.path.exists(input_file):
                        raise FileNotFoundError(f"File not found: {input_file}")
                    
                    # Check file size
                    file_size = os.path.getsize(input_file)
                    if file_size == 0:
                        raise ValueError("File is empty")
                    
                    # Determine output path
                    output_image = self.kwargs.get('output_image')
                    if not output_image:
                        # Generate output filename in same directory as input file
                        input_dir = os.path.dirname(input_file) or '.'
                        base_name = os.path.splitext(os.path.basename(input_file))[0]
                        output_image = os.path.join(input_dir, f"{base_name}_stego.png")
                    
                    # Ensure output directory exists
                    output_dir = os.path.dirname(output_image)
                    if output_dir and not os.path.exists(output_dir):
                        try:
                            os.makedirs(output_dir, exist_ok=True)
                        except Exception as e:
                            raise PermissionError(f"Cannot create output directory: {e}")
                    
                    # Check if output directory is writable
                    if output_dir and not os.access(output_dir, os.W_OK):
                        raise PermissionError(f"Output directory is not writable: {output_dir}")
                    
                    self.message.emit(f"Embedding file: {os.path.basename(input_file)}")
                    self.message.emit(f"Output will be: {output_image}")
                    
                    # Show auto-actions if any were taken
                    auto_actions = getattr(engine, '_auto_actions', [])
                    for action in auto_actions:
                        self.message.emit(f"ℹ {action}")
                    
                    success = engine.embed_file(
                        input_file=input_file,
                        cover_image=self.kwargs.get('cover_image'),
                        output_image=output_image,
                        password=self.kwargs.get('password'),
                        mode=self.kwargs.get('mode', 'pixel'),
                        compress=self.kwargs.get('compress', False),
                        quality=self.kwargs.get('quality', 95),
                        show_progress=False,
                        strip_metadata=self.kwargs.get('strip_metadata', False),
                        enable_robustness=self.kwargs.get('robustness', False),
                        enable_anti_steganalysis=self.kwargs.get('anti_steganalysis', False)
                    )
                    
                    if success:
                        # Verify output file was created
                        if os.path.exists(output_image):
                            output_size = os.path.getsize(output_image)
                            self.message.emit(f"File embedded successfully: {output_image}")
                            self.message.emit(f"Output size: {output_size:,} bytes")
                        else:
                            error_msg = f"Warning: Embedding returned success but output file not found: {output_image}"
                            self.message.emit(error_msg)
                            success = False
                    else:
                        # Get detailed error message if available
                        error_msg = getattr(engine, '_last_error', None)
                        if error_msg:
                            self.message.emit(f"Failed to embed file: {error_msg}")
                        else:
                            self.message.emit("Failed to embed file - check file format and size")
                        self.message.emit("Check console/log for detailed error messages")
                        
                except FileNotFoundError as e:
                    self.message.emit(f"Error: {str(e)}")
                    success = False
                except PermissionError as e:
                    self.message.emit(f"Permission error: {str(e)}")
                    success = False
                except ValueError as e:
                    self.message.emit(f"Error: {str(e)}")
                    success = False
                except Exception as e:
                    error_msg = f"Error embedding file: {type(e).__name__}: {str(e)}"
                    self.message.emit(error_msg)
                    tb = traceback.format_exc()
                    # Send traceback line by line to avoid message length issues
                    for line in tb.split('\n')[-10:]:  # Last 10 lines of traceback
                        if line.strip():
                            self.message.emit(line)
                    success = False
                
                self.finished.emit(success, output_image if 'output_image' in locals() else self.kwargs.get('output_image', ''))
            
            elif self.operation == 'extract':
                # Extract file - core.py will automatically use original filename/extension from metadata
                # If user specified a directory, it will use original filename in that directory
                # If user specified a file path, it will correct the extension automatically
                try:
                    extracted = engine.extract_file(
                        stego_image=self.kwargs['stego_image'],
                        output_path=self.kwargs.get('output_path'),
                        password=self.kwargs.get('password'),
                        verify=self.kwargs.get('verify', True)
                    )
                    if extracted:
                        self.message.emit(f"File extracted successfully: {extracted}")
                        self.finished.emit(True, extracted)
                    else:
                        # Get detailed error message if available
                        error_msg = getattr(engine, '_last_error', None)
                        if error_msg:
                            self.message.emit(f"Failed to extract file: {error_msg}")
                        else:
                            self.message.emit("Failed to extract file - check password and image format")
                        self.finished.emit(False, '')
                except ValueError as e:
                    # Password errors and validation errors
                    error_msg = str(e)
                    self.message.emit(f"Error: {error_msg}")
                    if "password" in error_msg.lower() or "incorrect" in error_msg.lower():
                        self.message.emit("Hint: Check if the password is correct")
                    self.finished.emit(False, '')
                except FileNotFoundError as e:
                    self.message.emit(f"Error: File not found - {str(e)}")
                    self.finished.emit(False, '')
                except PermissionError as e:
                    self.message.emit(f"Permission error: {str(e)}")
                    self.message.emit("Hint: Check write permissions for output directory")
                    self.finished.emit(False, '')
                except Exception as e:
                    error_msg = f"Error extracting file: {type(e).__name__}: {str(e)}"
                    self.message.emit(error_msg)
                    # Get error from engine if available
                    engine_error = getattr(engine, '_last_error', None)
                    if engine_error:
                        self.message.emit(f"Details: {engine_error}")
                    tb = traceback.format_exc()
                    # Send last few lines of traceback
                    for line in tb.split('\n')[-5:]:
                        if line.strip() and 'File' in line:
                            self.message.emit(line)
                    self.finished.emit(False, '')
            
            elif self.operation == 'embed-archive':
                try:
                    success = engine.embed_archive(
                        file_paths=self.kwargs['file_paths'],
                        cover_image=self.kwargs.get('cover_image'),
                        output_image=self.kwargs['output_image'],
                        password=self.kwargs.get('password'),
                        mode=self.kwargs.get('mode', 'lsb'),
                        compress=self.kwargs.get('compress', True),
                        strip_metadata=self.kwargs.get('strip_metadata', False),
                        enable_robustness=self.kwargs.get('robustness', False),
                        enable_anti_steganalysis=self.kwargs.get('anti_steganalysis', False)
                    )
                    if success:
                        output_image = self.kwargs['output_image']
                        if os.path.exists(output_image):
                            output_size = os.path.getsize(output_image)
                            self.message.emit(f"Archive embedded successfully: {output_image}")
                            self.message.emit(f"Output size: {output_size:,} bytes")
                        self.finished.emit(True, output_image)
                    else:
                        error_msg = getattr(engine, '_last_error', None)
                        if error_msg:
                            self.message.emit(f"Failed to embed archive: {error_msg}")
                        else:
                            self.message.emit("Failed to embed archive")
                        self.finished.emit(False, '')
                except Exception as e:
                    error_msg = f"Error embedding archive: {type(e).__name__}: {str(e)}"
                    self.message.emit(error_msg)
                    self.finished.emit(False, '')
            
            elif self.operation == 'extract-archive':
                try:
                    result = engine.extract_archive(
                        stego_image=self.kwargs['stego_image'],
                        output_dir=self.kwargs.get('output_dir', '.'),
                        password=self.kwargs.get('password'),
                        enable_robustness=self.kwargs.get('robustness', False)
                    )
                    if result:
                        self.message.emit(f"Archive extracted successfully")
                        self.message.emit(f"Extracted {result['file_count']} file(s)")
                        self.message.emit(f"Total size: {result['total_size']:,} bytes")
                        self.finished.emit(True, str(result))
                    else:
                        self.message.emit("Failed to extract archive")
                        self.finished.emit(False, '')
                except Exception as e:
                    error_msg = f"Error extracting archive: {type(e).__name__}: {str(e)}"
                    self.message.emit(error_msg)
                    self.finished.emit(False, '')
        
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            # Include traceback for debugging
            tb = traceback.format_exc()
            self.message.emit(error_msg)
            self.message.emit(f"Details: {tb}")
            self.finished.emit(False, '')


class StegoVaultGUI(QMainWindow):
    """Main GUI window"""
    
    def __init__(self):
        super().__init__()
        self.engine = StegoEngine(enable_robustness=False, enable_anti_steganalysis=False)
        self.worker: Optional[StegoWorker] = None
        self._header_logo_label: Optional[QLabel] = None
        self._header_brand_pixmap: Optional[QPixmap] = None
        self._header_widget: Optional[QWidget] = None
        self._header_subtitle_label: Optional[QLabel] = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize the UI"""
        self.setWindowTitle(f"{APP_NAME} - {APP_TAGLINE}")
        self.setGeometry(100, 100, 800, 600)

        # App branding (icon + visible logo)
        self._apply_branding()

        # Theme / styling
        self._apply_theme()

        # Menu (About)
        self._setup_menu()
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(10)
        central_widget.setLayout(main_layout)

        # Header
        header = self._create_header_widget()
        if header is not None:
            main_layout.addWidget(header)
        
        # Main content area with a guided workflow column and a side intelligence panel
        content_layout = QHBoxLayout()
        content_layout.setSpacing(12)
        main_layout.addLayout(content_layout)

        # Main card (primary container)
        main_card = QWidget()
        main_card.setObjectName("MainCard")
        main_card_layout = QVBoxLayout()
        main_card_layout.setContentsMargins(14, 14, 14, 14)
        main_card_layout.setSpacing(10)
        main_card.setLayout(main_card_layout)
        content_layout.addWidget(main_card, stretch=3)

        left_column = QVBoxLayout()
        left_column.setSpacing(10)
        main_card_layout.addLayout(left_column)

        tabs = QTabWidget()
        left_column.addWidget(tabs)
        
        embed_tab = self.create_embed_tab()
        tabs.addTab(embed_tab, "Embed File")
        
        archive_tab = self.create_archive_tab()
        tabs.addTab(archive_tab, "Embed Archive")
        
        extract_tab = self.create_extract_tab()
        tabs.addTab(extract_tab, "Extract File")
        
        extract_archive_tab = self.create_extract_archive_tab()
        tabs.addTab(extract_archive_tab, "Extract Archive")
        
        capacity_tab = self.create_capacity_tab()
        tabs.addTab(capacity_tab, "Capacity")
        
        detect_tab = self.create_detect_tab()
        tabs.addTab(detect_tab, "Detect")
        
        privacy_tab = self.create_privacy_tab()
        tabs.addTab(privacy_tab, "Privacy")
        
        info_tab = self.create_info_tab()
        tabs.addTab(info_tab, "View Info")

        about_tab = self.create_about_tab()
        tabs.addTab(about_tab, "About")

        # Intelligence / Status panel on the right
        right_panel = QGroupBox("Status & Intelligence")
        right_panel.setObjectName("IntelligencePanel")
        right_layout = QVBoxLayout()
        right_layout.setSpacing(8)
        right_layout.setContentsMargins(12, 12, 12, 12)

        # Readiness status with icon
        self.status_readiness_label = QLabel("⏳ Ready to embed")
        self.status_readiness_label.setWordWrap(True)
        self.status_readiness_label.setStyleSheet("font-weight: 600; color: rgba(76,175,80,0.95);")
        right_layout.addWidget(self.status_readiness_label)

        # Mode explanation
        self.status_mode_label = QLabel("Mode: pixel — higher capacity, lower robustness")
        self.status_mode_label.setWordWrap(True)
        self.status_mode_label.setStyleSheet("color: rgba(230,234,242,0.80); font-size: 12px;")
        right_layout.addWidget(self.status_mode_label)

        # Capacity estimation
        self.status_capacity_label = QLabel("Capacity: —")
        self.status_capacity_label.setWordWrap(True)
        self.status_capacity_label.setStyleSheet("color: rgba(230,234,242,0.75); font-size: 11px;")
        right_layout.addWidget(self.status_capacity_label)

        # Detectability risk
        self.status_detectability_label = QLabel("Detectability: —")
        self.status_detectability_label.setWordWrap(True)
        self.status_detectability_label.setStyleSheet("color: rgba(230,234,242,0.75); font-size: 11px;")
        right_layout.addWidget(self.status_detectability_label)

        # Security summary
        self.status_security_label = QLabel("Security:\n• Encryption: None\n• Robustness: Off\n• Anti-analysis: Off\n• Compression: Off")
        self.status_security_label.setWordWrap(True)
        self.status_security_label.setStyleSheet("color: rgba(230,234,242,0.80); font-size: 11px; margin-top: 8px;")
        right_layout.addWidget(self.status_security_label)

        right_layout.addStretch()
        right_panel.setLayout(right_layout)
        content_layout.addWidget(right_panel, stretch=1)
        
        self.statusBar().showMessage("Ready")
        
        # System console (progress + log)
        console_panel = QGroupBox("System Console")
        console_panel.setObjectName("ConsolePanel")
        console_layout = QVBoxLayout()
        console_layout.setContentsMargins(12, 10, 12, 10)
        console_layout.setSpacing(8)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        console_layout.addWidget(self.progress_bar)

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setMaximumHeight(170)
        self.log_area.setStyleSheet("background: rgba(9,11,41,0.85); border: none; color: rgba(230,234,242,0.85); font-family: 'Monaco', 'Courier New', monospace; font-size: 11px;")
        self.log_area.setPlaceholderText("System Console — Operation logs, diagnostics, and output will appear here.\n\nReady to process operations.")
        console_layout.addWidget(self.log_area)
        
        # Initialize console with welcome message (after widget is added)
        QApplication.processEvents()  # Ensure widget is ready
        self.log("StegoVault initialized. Ready for operations.", "info")

        console_panel.setLayout(console_layout)
        left_column.addWidget(console_panel)

        # Initial status summary
        self.update_status_summary()

    def resizeEvent(self, event):
        """Keep header logo scaled nicely as the window resizes."""
        try:
            self._update_header_logo()
        finally:
            super().resizeEvent(event)

    def _apply_theme(self) -> None:
        """Apply a modern dark theme aligned with the logo's neon-blue palette."""
        try:
            app = QApplication.instance()
            if app is None:
                return

            # Use Fusion for consistent cross-platform rendering
            app.setStyle("Fusion")

            # Core background from brand logo: RGBA (9, 11, 41, 1) -> #090B29
            brand_bg = QColor(9, 11, 41)
            surface_bg = QColor(14, 18, 60)   # slightly lighter for cards / panes
            input_bg = QColor(12, 16, 52)
            accent = QColor(56, 189, 248)     # neon-ish blue accent

            # Dark palette based on brand background
            palette = QPalette()
            palette.setColor(QPalette.ColorRole.Window, brand_bg)
            palette.setColor(QPalette.ColorRole.WindowText, QColor("#E6EAF2"))
            palette.setColor(QPalette.ColorRole.Base, input_bg)
            palette.setColor(QPalette.ColorRole.AlternateBase, surface_bg)
            palette.setColor(QPalette.ColorRole.ToolTipBase, input_bg)
            palette.setColor(QPalette.ColorRole.ToolTipText, QColor("#E6EAF2"))
            palette.setColor(QPalette.ColorRole.Text, QColor("#E6EAF2"))
            palette.setColor(QPalette.ColorRole.Button, surface_bg)
            palette.setColor(QPalette.ColorRole.ButtonText, QColor("#E6EAF2"))
            palette.setColor(QPalette.ColorRole.BrightText, QColor("#FFFFFF"))
            palette.setColor(QPalette.ColorRole.Highlight, accent)
            palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#050816"))
            app.setPalette(palette)

            # QSS on top of palette for a cleaner “product UI”
            app.setStyleSheet("""
                QMainWindow {
                    background: #090B29;
                }
                QWidget {
                    font-size: 13px;
                }
                QWidget#MainCard {
                    background: rgba(9,11,41,0.62);
                    border: 1px solid rgba(240,245,255,0.22);
                    border-radius: 16px;
                }
                QGroupBox {
                    /* Soft, light outline for major sections */
                    border: none;
                    border-radius: 10px;
                    margin-top: 10px;
                    padding: 10px;
                    /* Keep cards very close to the brand background so everything “melts” */
                    background: transparent;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    left: 10px;
                    padding: 0 6px;
                    color: rgba(255,255,255,0.92); /* bright but not harsh */
                    font-weight: 600;
                    font-size: 14px;
                }
                QGroupBox#IntelligencePanel, QGroupBox#ConsolePanel {
                    border: 1px solid rgba(240,245,255,0.25);
                    border-radius: 14px;
                    background: rgba(9,11,41,0.55);
                }
                QLineEdit, QTextEdit, QComboBox {
                    background: #0C1034;
                    border: 1px solid rgba(255,255,255,0.12);
                    border-radius: 8px;
                    padding: 10px 12px;
                }
                QLineEdit:focus, QTextEdit:focus, QComboBox:focus {
                    border: 1px solid rgba(56,189,248,0.75);
                }
                QTabWidget::pane {
                    border: 1px solid rgba(255,255,255,0.10);
                    border-radius: 12px;
                    padding: 8px;
                    background: rgba(9,11,41,0.60);
                }
                QTabBar::tab {
                    background: rgba(12,16,52,0.9);
                    border: 1px solid rgba(255,255,255,0.10);
                    padding: 10px 14px;
                    margin-right: 6px;
                    border-top-left-radius: 10px;
                    border-top-right-radius: 10px;
                    color: rgba(230,234,242,0.85);
                }
                QTabBar::tab:selected {
                    background: rgba(56,189,248,0.18);
                    border: 1px solid rgba(56,189,248,0.40);
                    color: #E6EAF2;
                }
                QPushButton {
                    background: rgba(20,26,78,0.95);
                    /* Gentle outline for buttons */
                    border: 1px solid rgba(240,245,255,0.22);
                    border-radius: 10px;
                    padding: 10px 12px;
                    font-weight: 600;
                }
                QPushButton:hover {
                    background: rgba(56,189,248,0.18);
                    border: 1px solid rgba(56,189,248,0.55);
                }
                QPushButton:pressed {
                    background: rgba(56,189,248,0.28);
                }
                QProgressBar {
                    border: 1px solid rgba(255,255,255,0.10);
                    border-radius: 8px;
                    height: 16px;
                    background: rgba(16,22,70,0.95);
                }
                QProgressBar::chunk {
                    border-radius: 8px;
                    background: #38BDF8;
                }
                QCheckBox {
                    spacing: 8px;
                }
                QCheckBox::indicator {
                    width: 18px;
                    height: 18px;
                }
                QStatusBar {
                    background: transparent;
                    color: rgba(230,234,242,0.75);
                }
            """)
        except Exception:
            # Theme should never break the app
            pass

    def _setup_menu(self) -> None:
        """Create a minimal menu with an About action."""
        try:
            help_menu = self.menuBar().addMenu("Help")
            about_action = QAction("About", self)
            about_action.triggered.connect(self.show_about_dialog)
            help_menu.addAction(about_action)
        except Exception:
            pass

    def _project_root(self) -> Path:
        """Return the project root directory."""
        if hasattr(sys, "_MEIPASS"):
            return Path(sys._MEIPASS)
        # gui/main_window.py -> gui/ -> project root
        return Path(__file__).resolve().parent.parent

    def _logo_path(self) -> Path:
        """Return the app icon path (prefers Python-gui.png)."""
        root = self._project_root()
        preferred = root / "gui" / "assets" / "Python-gui.png"
        if preferred.exists():
            return preferred
        # Fallback to existing file if the preferred isn't present
        fallback = root / "gui" / "assets" / "logo.png"
        return fallback

    def _brand_logo_path(self) -> Path:
        """Return the full brand/logo image for headers/about (prefers logo.png)."""
        root = self._project_root()
        preferred = root / "gui" / "assets" / "logo.png"
        if preferred.exists():
            return preferred
        # Fallback to icon if full logo is missing
        fallback = root / "gui" / "assets" / "Python-gui.png"
        return fallback

    def _apply_branding(self) -> None:
        """Set window/app icon if available."""
        try:
            icon_path = self._logo_path()
            if icon_path.exists():
                icon = QIcon(str(icon_path))
                self.setWindowIcon(icon)
                # Also set app icon so it shows in task switcher/dock where supported
                app = QApplication.instance()
                if app is not None:
                    app.setWindowIcon(icon)
        except Exception:
            # Branding should never break the app
            pass

    def _create_header_widget(self) -> Optional[QWidget]:
        """Create a polished header (logo + title + subtitle)."""
        try:
            brand_path = self._brand_logo_path()
            if not brand_path.exists():
                return None

            pixmap = QPixmap(str(brand_path))
            if pixmap.isNull():
                return None
            self._header_brand_pixmap = pixmap

            # Full brand logo (centered), scaled to fit without cropping
            logo_label = QLabel()
            logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            logo_label.setStyleSheet("background: transparent; border: none; padding: 0;")
            self._header_logo_label = logo_label

            header = QWidget()
            header.setObjectName("HeaderBar")
            self._header_widget = header
            header.setStyleSheet("""
                QWidget#HeaderBar {
                    background: #090B29;  /* match logo background exactly */
                    /* remove borders so the logo background fully melts into the app background */
                    border: none;
                    border-radius: 14px;
                }
            """)
            col = QVBoxLayout()
            # Tight margins so the logo isn't visually cropped
            col.setContentsMargins(8, 10, 8, 12)
            col.setSpacing(6)

            # Give the header extra space for the full logo image
            logo_label.setMinimumHeight(260)
            self._update_header_logo()

            # Optional subtitle row (small, centered)
            subtitle = QLabel(f"{APP_TAGLINE}  •  v{APP_VERSION}")
            subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
            subtitle.setStyleSheet("color: rgba(230,234,242,0.68);")
            self._header_subtitle_label = subtitle

            col.addWidget(logo_label, alignment=Qt.AlignmentFlag.AlignHCenter)
            col.addWidget(subtitle, alignment=Qt.AlignmentFlag.AlignHCenter)

            header.setLayout(col)
            return header
        except Exception:
            return None

    def _update_header_logo(self) -> None:
        """Scale the header brand logo to show fully, using height so it isn't cut."""
        if self._header_logo_label is None or self._header_brand_pixmap is None:
            return
        try:
            # Prefer computing from the header widget to avoid any layout clipping
            if self._header_widget is not None and self._header_subtitle_label is not None:
                available = self._header_widget.height()
                # subtract margins + subtitle + spacing
                available -= 10 + 12  # top/bottom margins
                available -= self._header_subtitle_label.sizeHint().height()
                available -= 6      # spacing
                target_height = max(210, available)
            else:
                target_height = max(210, self._header_logo_label.height() or 0)

            scaled = self._header_brand_pixmap.scaledToHeight(
                target_height,
                Qt.TransformationMode.SmoothTransformation,
            )
            self._header_logo_label.setPixmap(scaled)
        except Exception:
            pass

    def show_about_dialog(self) -> None:
        """Show an About dialog with version info."""
        text = (
            f"<b>{APP_NAME}</b> v{APP_VERSION}<br>"
            f"{APP_TAGLINE}<br><br>"
            "StegoVault helps you hide files inside images using steganography, with optional encryption and privacy tools.<br><br>"
            "<span style='color:rgba(230,234,242,0.75)'>Tip:</span> Use <b>LSB</b> mode for more natural-looking images."
        )
        msg = QMessageBox(self)
        msg.setWindowTitle(f"About {APP_NAME}")
        msg.setTextFormat(Qt.TextFormat.RichText)
        msg.setText(text)
        # Use the same app icon if present
        try:
            icon_path = self._logo_path()
            if icon_path.exists():
                msg.setIconPixmap(QPixmap(str(icon_path)).scaled(72, 72, Qt.AspectRatioMode.KeepAspectRatio,
                                                               Qt.TransformationMode.SmoothTransformation))
        except Exception:
            pass
        msg.exec()
    
    def create_embed_tab(self) -> QWidget:
        """Create the embed tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(10)
        widget.setLayout(layout)

        def section(title: str) -> QVBoxLayout:
            """Create a soft section header and return its content layout."""
            title_label = QLabel(title)
            title_label.setStyleSheet("color: rgba(255,255,255,0.95); font-size: 15px; font-weight: 700;")
            divider = QLabel()
            divider.setFixedHeight(1)
            divider.setStyleSheet("background: rgba(240,245,255,0.18);")
            layout.addWidget(title_label)
            layout.addWidget(divider)
            content = QVBoxLayout()
            content.setSpacing(8)
            wrapper = QWidget()
            wrapper.setLayout(content)
            layout.addWidget(wrapper)
            return content
        
        # Input file
        input_layout = section("📥 Input")
        self.input_file_label = QLabel("No file selected")
        input_btn = QPushButton("Select File")
        input_btn.clicked.connect(self.select_input_file)
        input_layout.addWidget(self.input_file_label)
        input_layout.addWidget(input_btn)
        # Cover image lives in the same high-level input step
        self.cover_image_label = QLabel("No cover image (will create new)")
        cover_btn = QPushButton("Select Cover Image")
        cover_btn.clicked.connect(self.select_cover_image)
        input_layout.addWidget(self.cover_image_label)
        input_layout.addWidget(cover_btn)
        
        # Password
        password_layout = section("🔐 Protection")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.textChanged.connect(self.update_status_summary)
        password_layout.addWidget(self.password_input)
        
        # Mode
        mode_layout = section("🧬 Embedding")
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(['pixel', 'lsb'])
        self.mode_combo.currentTextChanged.connect(self.update_status_summary)
        mode_layout.addWidget(self.mode_combo)
        
        # Advanced features (collapsible)
        self.compress_check = QCheckBox("Compress data")
        self.compress_check.stateChanged.connect(self.update_status_summary)

        advanced_toggle = QPushButton("Show advanced options ▸")
        advanced_toggle.setCheckable(True)
        advanced_toggle.setChecked(False)
        advanced_toggle.setStyleSheet("QPushButton { border: 0; color: rgba(255,255,255,0.75); text-align: left; padding: 4px 0; }")

        self.advanced_group = QGroupBox("Advanced Features")
        advanced_layout = QVBoxLayout()
        self.robustness_check = QCheckBox("Enable social media robustness")
        self.anti_steganalysis_check = QCheckBox("Enable anti-steganalysis protection")
        self.strip_metadata_check = QCheckBox("Strip metadata from cover image")
        for chk in (self.robustness_check, self.anti_steganalysis_check, self.strip_metadata_check):
            chk.stateChanged.connect(self.update_status_summary)
        advanced_layout.addWidget(self.robustness_check)
        advanced_layout.addWidget(self.anti_steganalysis_check)
        advanced_layout.addWidget(self.strip_metadata_check)
        self.advanced_group.setLayout(advanced_layout)

        self.advanced_group.setVisible(False)
        advanced_toggle.toggled.connect(lambda checked: self._toggle_advanced(checked, advanced_toggle))

        layout.addWidget(self.compress_check)
        layout.addWidget(advanced_toggle)
        layout.addWidget(self.advanced_group)
        
        # Output file
        output_layout = section("📤 Output")
        self.output_file_label = QLabel("Will auto-generate filename")
        output_btn = QPushButton("Choose Output File")
        output_btn.clicked.connect(self.select_output_file)
        output_layout.addWidget(self.output_file_label)
        output_layout.addWidget(output_btn)
        
        # Embed button
        embed_btn = QPushButton("Embed File")
        embed_btn.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold; padding: 10px;")
        embed_btn.clicked.connect(self.embed_file)
        layout.addWidget(embed_btn)
        
        layout.addStretch()
        
        self.input_file_path = None
        self.cover_image_path = None
        self.output_file_path = None
        
        return widget
    
    def create_extract_tab(self) -> QWidget:
        """Create the extract tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Stego image
        image_group = QGroupBox("Stego Image")
        image_layout = QVBoxLayout()
        self.stego_image_label = QLabel("No image selected")
        image_btn = QPushButton("Select Stego Image")
        image_btn.clicked.connect(self.select_stego_image)
        image_layout.addWidget(self.stego_image_label)
        image_layout.addWidget(image_btn)
        image_group.setLayout(image_layout)
        layout.addWidget(image_group)
        
        # Password
        password_group = QGroupBox("Password (if encrypted)")
        password_layout = QVBoxLayout()
        self.extract_password_input = QLineEdit()
        self.extract_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        password_layout.addWidget(self.extract_password_input)
        password_group.setLayout(password_layout)
        layout.addWidget(password_group)
        
        # Verify
        self.verify_check = QCheckBox("Verify integrity")
        self.verify_check.setChecked(True)
        layout.addWidget(self.verify_check)
        
        # Output location
        output_group = QGroupBox("Extract To")
        output_layout = QVBoxLayout()
        self.extract_output_label = QLabel("Will extract to current directory with original filename")
        
        buttons_layout = QHBoxLayout()
        output_file_btn = QPushButton("Choose File Location")
        output_file_btn.clicked.connect(self.select_extract_output_file)
        output_dir_btn = QPushButton("Choose Directory")
        output_dir_btn.clicked.connect(self.select_extract_output_dir)
        buttons_layout.addWidget(output_file_btn)
        buttons_layout.addWidget(output_dir_btn)
        
        output_layout.addWidget(self.extract_output_label)
        output_layout.addLayout(buttons_layout)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        # Extract button
        extract_btn = QPushButton("Extract File")
        extract_btn.setStyleSheet("background-color: #2196F3; color: white; font-weight: bold; padding: 10px;")
        extract_btn.clicked.connect(self.extract_file)
        layout.addWidget(extract_btn)
        
        layout.addStretch()
        
        self.stego_image_path = None
        self.extract_output_path = None
        
        return widget
    
    def create_info_tab(self) -> QWidget:
        """Create the info tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Image selection
        info_image_group = QGroupBox("Stego Image")
        info_image_layout = QVBoxLayout()
        self.info_image_label = QLabel("No image selected")
        info_image_btn = QPushButton("Select Image")
        info_image_btn.clicked.connect(self.select_info_image)
        info_image_layout.addWidget(self.info_image_label)
        info_image_layout.addWidget(info_image_btn)
        info_image_group.setLayout(info_image_layout)
        layout.addWidget(info_image_group)
        
        # Password
        info_password_group = QGroupBox("Password (if encrypted)")
        info_password_layout = QVBoxLayout()
        self.info_password_input = QLineEdit()
        self.info_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        info_password_layout.addWidget(self.info_password_input)
        info_password_group.setLayout(info_password_layout)
        layout.addWidget(info_password_group)
        
        # Info display
        self.info_display = QTextEdit()
        self.info_display.setReadOnly(True)
        layout.addWidget(self.info_display)
        
        # View button
        view_btn = QPushButton("View Info")
        view_btn.setStyleSheet("background-color: #FF9800; color: white; font-weight: bold; padding: 10px;")
        view_btn.clicked.connect(self.view_info)
        layout.addWidget(view_btn)
        
        self.info_image_path = None
        
        return widget

    def create_about_tab(self) -> QWidget:
        """Create an about tab with version + short documentation."""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)
        widget.setLayout(layout)

        # Top card: logo + name/version
        card = QGroupBox("About")
        card_layout = QHBoxLayout()
        card_layout.setContentsMargins(14, 14, 14, 14)
        card_layout.setSpacing(12)

        logo_path = self._brand_logo_path()
        logo_label = QLabel()
        if logo_path.exists():
            pm = QPixmap(str(logo_path))
            if not pm.isNull():
                # Use the full logo and keep it crisp; avoid rounded backgrounds that “cut” edges
                logo_label.setPixmap(
                    pm.scaledToWidth(520, Qt.TransformationMode.SmoothTransformation)
                )
        logo_label.setMinimumHeight(200)
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo_label.setStyleSheet("background: transparent; border: none; padding: 0;")

        name = QLabel(f"{APP_NAME} <span style='color:rgba(230,234,242,0.70)'>v{APP_VERSION}</span>")
        name.setTextFormat(Qt.TextFormat.RichText)
        name_font = QFont()
        name_font.setPointSize(20)
        name_font.setBold(True)
        name.setFont(name_font)

        tagline = QLabel(APP_TAGLINE)
        tagline.setStyleSheet("color: rgba(230,234,242,0.75);")

        blurb = QLabel(
            "StegoVault hides files inside images using steganography, with optional encryption and privacy tools.\n"
            "It’s designed to be practical, cross‑platform, and easy to use."
        )
        blurb.setWordWrap(True)
        blurb.setStyleSheet("color: rgba(230,234,242,0.82);")

        text_col = QVBoxLayout()
        text_col.setContentsMargins(0, 0, 0, 0)
        text_col.setSpacing(4)
        text_col.addWidget(name)
        text_col.addWidget(tagline)
        text_col.addSpacing(6)
        text_col.addWidget(blurb)

        card_layout.addWidget(logo_label, alignment=Qt.AlignmentFlag.AlignTop)
        card_layout.addLayout(text_col)
        card_layout.addStretch()
        card.setLayout(card_layout)
        layout.addWidget(card)

        # Quick-start + tips
        tips = QGroupBox("Quick Start")
        tips_layout = QVBoxLayout()
        tips_layout.setContentsMargins(14, 14, 14, 14)
        tips_layout.setSpacing(8)

        tips_text = QTextEdit()
        tips_text.setReadOnly(True)
        tips_text.setMinimumHeight(280)
        tips_text.setStyleSheet("background: transparent; border: none; color: rgba(230,234,242,0.85); font-size: 12px;")
        tips_html = """
        <h3 style="color: rgba(230,234,242,0.95); margin-top: 0;">📥 Embedding a File</h3>
        <ol style="margin: 8px 0; padding-left: 20px;">
            <li>Open the <b>Embed File</b> tab</li>
            <li>Select a file to embed (any file type)</li>
            <li>(Optional) Choose a cover image, or let StegoVault create one</li>
            <li>(Optional) Set a password for AES-256 encryption</li>
            <li>Choose embedding mode (pixel or LSB)</li>
            <li>Click <b>Embed File</b></li>
        </ol>
        
        <h3 style="color: rgba(230,234,242,0.95);">📤 Extracting a File</h3>
        <ol style="margin: 8px 0; padding-left: 20px;">
            <li>Open the <b>Extract File</b> tab</li>
            <li>Select the stego image containing hidden data</li>
            <li>Enter password if encryption was used</li>
            <li>Click <b>Extract File</b></li>
        </ol>
        
        <h3 style="color: rgba(230,234,242,0.95);">💡 Pro Tips</h3>
        <ul style="margin: 8px 0; padding-left: 20px;">
            <li><b>LSB mode</b> produces more natural-looking images (stealthier)</li>
            <li><b>Pixel mode</b> offers higher capacity but is more detectable</li>
            <li>Enable <b>robustness</b> if sharing via social media (adds error correction)</li>
            <li>Enable <b>anti-steganalysis</b> to reduce detection risk</li>
            <li>Use the <b>Privacy</b> tab to inspect and strip metadata</li>
            <li>Check <b>Capacity</b> tab to estimate if your file will fit</li>
        </ul>
        
        <h3 style="color: rgba(230,234,242,0.95);">🔒 Security Features</h3>
        <ul style="margin: 8px 0; padding-left: 20px;">
            <li>AES-256 encryption (optional password protection)</li>
            <li>Metadata stripping for privacy</li>
            <li>Anti-steganalysis protection</li>
            <li>Social media robustness (error correction)</li>
        </ul>
        """
        tips_text.setHtml(tips_html)
        tips_layout.addWidget(tips_text)
        tips.setLayout(tips_layout)
        layout.addWidget(tips)

        layout.addStretch()
        return widget
    
    def log(self, message: str, level: str = "info"):
        """Add message to log area with timestamp and formatting."""
        if not hasattr(self, 'log_area') or self.log_area is None:
            return
        
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color coding for different log levels
        if level == "error":
            formatted = f'<span style="color: #FF6B6B;">[{timestamp}] ERROR: {message}</span>'
        elif level == "success":
            formatted = f'<span style="color: #4CAF50;">[{timestamp}] ✓ {message}</span>'
        elif level == "warning":
            formatted = f'<span style="color: #FFA726;">[{timestamp}] ⚠ {message}</span>'
        else:
            formatted = f'<span style="color: rgba(230,234,242,0.85);">[{timestamp}] {message}</span>'
        
        # Use insertHtml for proper HTML rendering
        try:
            cursor = self.log_area.textCursor()
            cursor.movePosition(cursor.MoveOperation.End)
            cursor.insertHtml(formatted + "<br>")
            self.log_area.setTextCursor(cursor)
            self.log_area.ensureCursorVisible()
        except Exception:
            # Fallback to plain text if HTML fails
            self.log_area.append(f"[{timestamp}] {message}")
        
        self.statusBar().showMessage(message, 3000)  # Show for 3 seconds
        # Keep status summary in sync with activity
        if hasattr(self, 'update_status_summary'):
            self.update_status_summary()

    def _toggle_advanced(self, checked: bool, toggle_button: QPushButton):
        """Show/hide advanced features in embed tab."""
        self.advanced_group.setVisible(checked)
        toggle_button.setText("Hide advanced options ▾" if checked else "Show advanced options ▸")
        self.update_status_summary()

    def update_status_summary(self):
        """Update the side intelligence panel with readiness, mode tips, capacity, detectability, and security summary."""
        # Readiness with better status indicators
        if getattr(self, "input_file_path", None):
            readiness = "✅ Ready to embed"
            self.status_readiness_label.setStyleSheet("font-weight: 600; color: rgba(76,175,80,0.95);")
        else:
            readiness = "⚠️ Missing input file"
            self.status_readiness_label.setStyleSheet("font-weight: 600; color: rgba(255,167,38,0.95);")
        self.status_readiness_label.setText(readiness)

        # Mode explanation
        mode = self.mode_combo.currentText() if hasattr(self, "mode_combo") else "pixel"
        if mode == "pixel":
            mode_tip = "Mode: pixel — higher capacity, lower robustness"
        else:
            mode_tip = "Mode: lsb — stealthier, lower capacity"
        self.status_mode_label.setText(mode_tip)

        # Capacity estimation (if file and cover are selected)
        capacity_text = "Capacity: —"
        if hasattr(self, "input_file_path") and self.input_file_path:
            try:
                file_size = os.path.getsize(self.input_file_path)
                file_size_kb = file_size / 1024
                
                if hasattr(self, "cover_image_path") and self.cover_image_path:
                    # Estimate capacity from cover image
                    try:
                        capacity_info = self.engine.get_capacity_info(cover_image=self.cover_image_path, mode=mode)
                        max_kb = capacity_info.get('max_kb', 0)
                        if max_kb > 0:
                            utilization = (file_size_kb / max_kb) * 100
                            if utilization <= 100:
                                capacity_text = f"Capacity: {utilization:.1f}% used ({file_size_kb:.1f} KB / {max_kb:.1f} KB)"
                            else:
                                capacity_text = f"Capacity: ⚠️ File too large ({file_size_kb:.1f} KB > {max_kb:.1f} KB)"
                    except Exception:
                        capacity_text = f"File size: {file_size_kb:.1f} KB"
                else:
                    capacity_text = f"File size: {file_size_kb:.1f} KB"
            except Exception:
                pass
        self.status_capacity_label.setText(capacity_text)

        # Detectability risk assessment
        detectability = "Detectability: —"
        if hasattr(self, "mode_combo"):
            mode = self.mode_combo.currentText()
            anti_steg = self.anti_steganalysis_check.isChecked() if hasattr(self, "anti_steganalysis_check") else False
            
            if mode == "lsb" and anti_steg:
                detectability = "Detectability: 🟢 Low (LSB + anti-analysis)"
            elif mode == "lsb":
                detectability = "Detectability: 🟡 Medium (LSB mode)"
            elif mode == "pixel" and anti_steg:
                detectability = "Detectability: 🟡 Medium (pixel + anti-analysis)"
            else:
                detectability = "Detectability: 🔴 High (pixel mode)"
        self.status_detectability_label.setText(detectability)

        # Security summary
        pwd = self.password_input.text().strip() if hasattr(self, "password_input") else ""
        encryption = "AES-256" if pwd else "None"
        robustness = "On" if hasattr(self, "robustness_check") and self.robustness_check.isChecked() else "Off"
        anti = "On" if hasattr(self, "anti_steganalysis_check") and self.anti_steganalysis_check.isChecked() else "Off"
        compression = "On" if hasattr(self, "compress_check") and self.compress_check.isChecked() else "Off"
        summary = (
            "Security:\n"
            f"• Encryption: {encryption}\n"
            f"• Robustness: {robustness}\n"
            f"• Anti-analysis: {anti}\n"
            f"• Compression: {compression}"
        )
        self.status_security_label.setText(summary)
    
    def select_input_file(self):
        """Select input file - allows all file types"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File to Embed", "", "All Files (*.*)"
        )
        if file_path:
            self.input_file_path = file_path
            self.input_file_label.setText(f"File: {os.path.basename(file_path)}")
    
    def select_cover_image(self):
        """Select cover image"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Cover Image", "", "Images (*.png *.jpg *.jpeg *.bmp *.tiff *.gif)"
        )
        if file_path:
            self.cover_image_path = file_path
            self.cover_image_label.setText(f"Cover: {os.path.basename(file_path)}")
        else:
            self.cover_image_path = None
            self.cover_image_label.setText("No cover image (will create new)")
    
    def select_output_file(self):
        """Select output file"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Output Image", "", "PNG Images (*.png)"
        )
        if file_path:
            # Ensure file ends with .png
            if not file_path.lower().endswith('.png'):
                file_path = file_path + '.png'
            self.output_file_path = file_path
            self.output_file_label.setText(f"Output: {os.path.basename(file_path)}")
    
    def select_stego_image(self):
        """Select stego image"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Stego Image", "", "PNG Images (*.png)"
        )
        if file_path:
            self.stego_image_path = file_path
            self.stego_image_label.setText(f"Image: {os.path.basename(file_path)}")
    
    def select_info_image(self):
        """Select image for info"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Image", "", "PNG Images (*.png)"
        )
        if file_path:
            self.info_image_path = file_path
            self.info_image_label.setText(f"Image: {os.path.basename(file_path)}")
    
    def select_extract_output_file(self):
        """Select output file location for extracted file"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Extracted File", "", "All Files (*.*)"
        )
        if file_path:
            self.extract_output_path = file_path
            self.extract_output_label.setText(f"Output file: {file_path}")
        else:
            self.extract_output_path = None
            self.extract_output_label.setText("Will extract to current directory with original filename")
    
    def select_extract_output_dir(self):
        """Select output directory for extracted file"""
        dir_path = QFileDialog.getExistingDirectory(
            self, "Choose Directory to Save Extracted File", ""
        )
        if dir_path:
            self.extract_output_path = dir_path + os.sep
            self.extract_output_label.setText(f"Output directory: {dir_path}")
        else:
            self.extract_output_path = None
            self.extract_output_label.setText("Will extract to current directory with original filename")
    
    def embed_file(self):
        """Embed file"""
        if not self.input_file_path:
            QMessageBox.warning(self, "Error", "Please select a file to embed")
            return
        
        password_text = self.password_input.text()
        # Get password exactly as entered, only strip if not empty
        password = password_text.strip() if password_text else None
        mode = self.mode_combo.currentText()
        compress = self.compress_check.isChecked()
        
        if not self.output_file_path:
            base_name = os.path.splitext(os.path.basename(self.input_file_path))[0]
            output_dir = os.path.dirname(self.input_file_path) or '.'
            self.output_file_path = os.path.join(output_dir, f"{base_name}_stego.png")
        
        self.log(f"Starting embedding operation: {os.path.basename(self.input_file_path)}", "info")
        self.log("Processing... This may take a moment depending on file size.", "info")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.status_readiness_label.setText("⏳ Processing...")
        self.status_readiness_label.setStyleSheet("font-weight: 600; color: rgba(56,189,248,0.95);")
        
        self.worker = StegoWorker(
            'embed',
            input_file=self.input_file_path,
            cover_image=self.cover_image_path,
            output_image=self.output_file_path,
            password=password,
            mode=mode,
            compress=compress,
            robustness=self.robustness_check.isChecked(),
            anti_steganalysis=self.anti_steganalysis_check.isChecked(),
            strip_metadata=self.strip_metadata_check.isChecked()
        )
        self.worker.finished.connect(self.on_embed_finished)
        self.worker.message.connect(self.log)
        self.worker.start()
        self.update_status_summary()
    
    def extract_file(self):
        """Extract file"""
        if not self.stego_image_path:
            QMessageBox.warning(self, "Error", "Please select a stego image")
            return
        
        password_text = self.extract_password_input.text()
        # Get password exactly as entered, only strip if not empty
        password = password_text.strip() if password_text else None
        
        self.log(f"Starting extraction operation: {os.path.basename(self.stego_image_path)}", "info")
        self.log("Processing... Decrypting and extracting hidden data.", "info")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.status_readiness_label.setText("⏳ Processing...")
        self.status_readiness_label.setStyleSheet("font-weight: 600; color: rgba(56,189,248,0.95);")
        
        self.worker = StegoWorker(
            'extract',
            stego_image=self.stego_image_path,
            output_path=self.extract_output_path,
            password=password,
            verify=self.verify_check.isChecked()
        )
        self.worker.finished.connect(self.on_extract_finished)
        self.worker.message.connect(self.log)
        self.worker.start()
        self.update_status_summary()
    
    def view_info(self):
        """View image metadata"""
        if not self.info_image_path:
            QMessageBox.warning(self, "Error", "Please select an image")
            return
        
        password_text = self.info_password_input.text()
        # Get password exactly as entered, only strip if not empty
        password = password_text.strip() if password_text else None
        
        try:
            metadata = self.engine.get_metadata(self.info_image_path, password)
            if metadata:
                info_text = "📋 Image Metadata\n"
                info_text += "=" * 40 + "\n\n"
                
                if metadata.get('is_archive', False):
                    info_text += f"Type: Archive (Multiple Files)\n"
                    info_text += f"File Count: {metadata['file_count']}\n"
                    info_text += f"Total Size: {metadata['total_size']:,} bytes\n"
                else:
                    info_text += f"Type: Single File\n"
                    info_text += f"File Name: {metadata['file_name']}\n"
                    info_text += f"File Size: {metadata['file_size']:,} bytes\n"
                
                info_text += f"Encrypted: {'Yes' if metadata['encrypted'] else 'No'}\n"
                info_text += f"Compressed: {'Yes' if metadata['compressed'] else 'No'}\n"
                info_text += f"Format Version: {metadata['version']}\n"
                
                self.info_display.setText(info_text)
                self.log("Metadata retrieved successfully")
            else:
                QMessageBox.warning(self, "Error", "Could not read metadata. File may not be a stego image.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to read metadata: {str(e)}")
    
    def on_embed_finished(self, success: bool, output_path: str):
        """Handle embed completion with enhanced feedback."""
        self.progress_bar.setVisible(False)
        # Reset status readiness
        self.update_status_summary()
        if success:
            try:
                if os.path.exists(output_path):
                    file_size = os.path.getsize(output_path)
                    size_mb = file_size / (1024 * 1024)
                    size_kb = file_size / 1024
                    size_str = f"{size_mb:.2f} MB" if size_mb >= 1 else f"{size_kb:.1f} KB"
                    
                    success_msg = (
                        f"✅ File embedded successfully!\n\n"
                        f"Output: {os.path.basename(output_path)}\n"
                        f"Location: {os.path.dirname(output_path) or 'Current directory'}\n"
                        f"Size: {size_str}\n\n"
                        f"Your hidden file is now safely stored in the image."
                    )
                    self.log(f"Embedding completed: {os.path.basename(output_path)} ({size_str})", "success")
                else:
                    success_msg = f"✅ File embedded successfully!\n\nOutput: {output_path}"
                    self.log("Embedding completed", "success")
            except Exception:
                success_msg = f"✅ File embedded successfully!\n\nOutput: {output_path}"
                self.log("Embedding completed", "success")
            
            QMessageBox.information(self, "Success", success_msg)
        else:
            # Get the last error message from log
            log_text = self.log_area.toPlainText()
            error_lines = [line for line in log_text.split('\n') if 'ERROR' in line.upper() or 'Failed' in line or 'Permission' in line or 'not found' in line.lower()]
            if error_lines:
                # Get the most recent error message (usually the most specific one)
                error_msg = error_lines[-1] if error_lines else "Failed to embed file"
                # Clean up HTML tags if present
                import re
                error_msg = re.sub(r'<[^>]+>', '', error_msg)
                if error_msg.startswith("Failed to embed file:"):
                    error_msg = error_msg.replace("Failed to embed file:", "").strip()
            else:
                error_msg = "Failed to embed file. Check the System Console for details."
            
            self.log(f"Embedding failed: {error_msg}", "error")
            QMessageBox.critical(self, "Error", f"❌ Failed to embed file.\n\n{error_msg}\n\nCheck the System Console below for detailed logs.")
    
    def on_extract_finished(self, success: bool, extracted_path: str):
        """Handle extract completion with enhanced feedback."""
        self.progress_bar.setVisible(False)
        # Reset status readiness
        self.update_status_summary()
        if success:
            try:
                if os.path.exists(extracted_path):
                    file_size = os.path.getsize(extracted_path)
                    size_mb = file_size / (1024 * 1024)
                    size_kb = file_size / 1024
                    size_str = f"{size_mb:.2f} MB" if size_mb >= 1 else f"{size_kb:.1f} KB"
                    
                    success_msg = (
                        f"✅ File extracted successfully!\n\n"
                        f"Output: {os.path.basename(extracted_path)}\n"
                        f"Location: {os.path.dirname(extracted_path) or 'Current directory'}\n"
                        f"Size: {size_str}\n\n"
                        f"The hidden file has been recovered from the image."
                    )
                    self.log(f"Extraction completed: {os.path.basename(extracted_path)} ({size_str})", "success")
                else:
                    success_msg = f"✅ File extracted successfully!\n\nOutput: {extracted_path}"
                    self.log("Extraction completed", "success")
            except Exception:
                success_msg = f"✅ File extracted successfully!\n\nOutput: {extracted_path}"
                self.log("Extraction completed", "success")
            
            QMessageBox.information(self, "Success", success_msg)
        else:
            # Get the last error message from log
            log_text = self.log_area.toPlainText()
            error_lines = [line for line in log_text.split('\n') if 'ERROR' in line.upper() or 'Failed' in line or 'password' in line.lower() or 'incorrect' in line.lower()]
            if error_lines:
                # Get the most recent error message
                error_msg = error_lines[-1]
                # Clean up HTML tags if present
                import re
                error_msg = re.sub(r'<[^>]+>', '', error_msg)
                if error_msg.startswith("Failed to extract file:"):
                    error_msg = error_msg.replace("Failed to extract file:", "").strip()
                elif error_msg.startswith("Error:"):
                    error_msg = error_msg.replace("Error:", "").strip()
            else:
                error_msg = "Failed to extract file. Check the System Console for details."
            
            self.log(f"Extraction failed: {error_msg}", "error")
            QMessageBox.critical(self, "Error", f"❌ Failed to extract file.\n\n{error_msg}\n\nCheck the System Console below for detailed logs.")
    
    # Archive tab handlers
    def select_archive_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files", "", "All Files (*.*)")
        if files:
            self.archive_file_paths.extend(files)
            self.archive_files_list.append('\n'.join([os.path.basename(f) for f in files]))
    
    def select_archive_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder:
            self.archive_file_paths.append(folder)
            self.archive_files_list.append(f"📁 {os.path.basename(folder)}")
    
    def select_archive_cover(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Cover Image", "", "Images (*.png *.jpg *.jpeg *.bmp *.tiff *.gif)"
        )
        if file_path:
            self.archive_cover_path = file_path
            self.archive_cover_label.setText(f"Cover: {os.path.basename(file_path)}")
        else:
            self.archive_cover_path = None
            self.archive_cover_label.setText("No cover image (will create new)")
    
    def select_archive_output(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Output Image", "", "PNG Images (*.png)"
        )
        if file_path:
            self.archive_output_path = file_path
            self.archive_output_label.setText(f"Output: {os.path.basename(file_path)}")
    
    def embed_archive(self):
        if not self.archive_file_paths:
            QMessageBox.warning(self, "Error", "Please select files or folders to embed")
            return
        
        password_text = self.archive_password_input.text()
        password = password_text.strip() if password_text else None
        
        if not self.archive_output_path:
            base_name = "archive"
            output_dir = os.path.dirname(self.archive_file_paths[0]) if self.archive_file_paths else '.'
            self.archive_output_path = os.path.join(output_dir, f"{base_name}_stego.png")
        
        self.log(f"Embedding archive with {len(self.archive_file_paths)} item(s)...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        self.worker = StegoWorker(
            'embed-archive',
            file_paths=self.archive_file_paths,
            cover_image=self.archive_cover_path,
            output_image=self.archive_output_path,
            password=password,
            compress=self.archive_compress_check.isChecked(),
            robustness=self.archive_robustness_check.isChecked(),
            anti_steganalysis=self.archive_anti_steganalysis_check.isChecked(),
            strip_metadata=self.archive_strip_metadata_check.isChecked()
        )
        self.worker.finished.connect(self.on_embed_finished)
        self.worker.message.connect(self.log)
        self.worker.start()
    
    def select_archive_stego_image(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Stego Image", "", "PNG Images (*.png)"
        )
        if file_path:
            self.archive_extract_image_path = file_path
            self.archive_stego_label.setText(f"Image: {os.path.basename(file_path)}")
    
    def select_archive_extract_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Choose Directory")
        if dir_path:
            self.archive_extract_output_dir = dir_path
            self.archive_extract_output_label.setText(f"Output directory: {dir_path}")
    
    def extract_archive(self):
        if not self.archive_extract_image_path:
            QMessageBox.warning(self, "Error", "Please select a stego image")
            return
        
        password_text = self.archive_extract_password.text()
        password = password_text.strip() if password_text else None
        
        self.log(f"Extracting archive from: {os.path.basename(self.archive_extract_image_path)}")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        self.worker = StegoWorker(
            'extract-archive',
            stego_image=self.archive_extract_image_path,
            output_dir=self.archive_extract_output_dir,
            password=password,
            robustness=self.archive_extract_robustness.isChecked()
        )
        self.worker.finished.connect(self.on_extract_archive_finished)
        self.worker.message.connect(self.log)
        self.worker.start()
    
    def on_extract_archive_finished(self, success: bool, result_data: str):
        self.progress_bar.setVisible(False)
        if success:
            QMessageBox.information(self, "Success", f"Archive extracted successfully!\n\nOutput: {self.archive_extract_output_dir}")
        else:
            QMessageBox.critical(self, "Error", "Failed to extract archive. Check the log for details.")
    
    # Capacity tab handlers
    def select_capacity_image(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Cover Image", "", "Images (*.png *.jpg *.jpeg *.bmp *.tiff *.gif)"
        )
        if file_path:
            self.capacity_image_path = file_path
            self.capacity_image_label.setText(f"Image: {os.path.basename(file_path)}")
    
    def select_capacity_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Check", "", "All Files (*.*)")
        if file_path:
            self.capacity_file_path = file_path
            self.capacity_file_label.setText(f"File: {os.path.basename(file_path)}")
    
    def calculate_capacity(self):
        if not self.capacity_image_path:
            QMessageBox.warning(self, "Error", "Please select a cover image")
            return
        
        mode = self.capacity_mode_combo.currentText()
        compress = self.capacity_compress_check.isChecked()
        
        capacity = self.engine.get_capacity_info(cover_image=self.capacity_image_path, mode=mode)
        
        result_text = f"📊 Capacity Analysis\n{'='*50}\n\n"
        result_text += f"Image: {os.path.basename(self.capacity_image_path)}\n"
        result_text += f"Size: {capacity['image_size'][0]}x{capacity['image_size'][1]} pixels\n"
        result_text += f"Mode: {capacity['mode']}\n\n"
        result_text += f"Capacity:\n"
        result_text += f"  Maximum: {capacity['max_kb']:.2f} KB ({capacity['max_mb']:.3f} MB)\n"
        if compress:
            result_text += f"  With Compression: {capacity['max_kb_compressed']:.2f} KB ({capacity['max_mb_compressed']:.3f} MB)\n"
        
        result_text += f"\nRecommendations:\n"
        for rec in capacity['recommendations']:
            result_text += f"  • {rec}\n"
        
        if self.capacity_file_path:
            fit_analysis = self.engine.check_file_fits(
                self.capacity_file_path, cover_image=self.capacity_image_path,
                mode=mode, compress=compress
            )
            result_text += f"\n{'='*50}\n"
            result_text += f"File Fit Analysis:\n"
            result_text += f"  File: {os.path.basename(self.capacity_file_path)}\n"
            result_text += f"  Size: {self.engine.capacity.format_size(fit_analysis['file_size'])}\n"
            result_text += f"  Fits: {'✅ Yes' if fit_analysis['fits'] else '❌ No'}\n"
            result_text += f"  Utilization: {fit_analysis['utilization_percent']:.1f}%\n"
            
            if fit_analysis['warnings']:
                result_text += f"\n⚠ Warnings:\n"
                for warning in fit_analysis['warnings']:
                    result_text += f"  • {warning}\n"
            
            if fit_analysis['recommendations']:
                result_text += f"\n💡 Recommendations:\n"
                for rec in fit_analysis['recommendations']:
                    result_text += f"  • {rec}\n"
        
        self.capacity_results.setText(result_text)
    
    # Detect tab handlers
    def select_detect_image(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Image", "", "PNG Images (*.png)"
        )
        if file_path:
            self.detect_image_path = file_path
            self.detect_image_label.setText(f"Image: {os.path.basename(file_path)}")
    
    def detect_steganography(self):
        if not self.detect_image_path:
            QMessageBox.warning(self, "Error", "Please select an image")
            return
        
        detection = self.engine.detect_steganography(self.detect_image_path)
        
        if 'error' in detection:
            self.detect_results.setText(f"Error: {detection['error']}")
            return
        
        result_text = f"🔍 Steganography Detection Results\n{'='*50}\n\n"
        result_text += f"Image: {os.path.basename(self.detect_image_path)}\n\n"
        result_text += f"Risk Score: {detection['risk_score']}/100\n"
        result_text += f"Risk Level: {detection['risk_level']}\n"
        result_text += f"Detected: {'⚠️ Yes' if detection['detected'] else '✅ No'}\n\n"
        
        result_text += f"LSB Analysis:\n"
        lsb = detection['lsb_analysis']
        result_text += f"  Transition Rate: {lsb['transition_rate']:.3f}\n"
        result_text += f"  Suspicious Patterns: {lsb['suspicious_patterns']:.3f}\n\n"
        
        result_text += f"Histogram Analysis:\n"
        hist = detection['histogram_analysis']
        result_text += f"  Anomaly Score: {hist['anomaly_score']:.3f}\n"
        result_text += f"  Anomalies Detected: {'Yes' if hist['anomalies_detected'] else 'No'}\n\n"
        
        result_text += f"RS Analysis:\n"
        rs = detection['rs_analysis']
        result_text += f"  Detected: {'Yes' if rs['detected'] else 'No'}\n"
        result_text += f"  Imbalance: {rs['imbalance']:.3f}\n"
        
        self.detect_results.setText(result_text)
    
    # Privacy tab handlers
    def select_privacy_image(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Image", "", "PNG Images (*.png)"
        )
        if file_path:
            self.privacy_image_path = file_path
            self.privacy_image_label.setText(f"Image: {os.path.basename(file_path)}")
    
    def analyze_privacy(self):
        if not self.privacy_image_path:
            QMessageBox.warning(self, "Error", "Please select an image")
            return
        
        # Run privacy analysis with safety wrapper to avoid crashes
        try:
            self.log("Starting privacy analysis...", "info")
            report = self.engine.get_privacy_report(self.privacy_image_path)
            
            result_text = f"🔒 Privacy Analysis\n{'='*50}\n\n"
            result_text += f"Image: {os.path.basename(self.privacy_image_path)}\n"
            result_text += f"File Size: {self.engine.capacity.format_size(report['metadata']['file_size'])}\n\n"
            
            if report['metadata']['has_exif']:
                result_text += f"⚠ EXIF Data Found\n"
                result_text += f"  Tags: {len(report['metadata']['exif'])}\n\n"
            
            if report['metadata']['has_gps']:
                result_text += f"⚠⚠ GPS Location Data Found!\n"
                result_text += f"  This reveals where the photo was taken\n\n"
            
            if report['privacy_risks']:
                result_text += f"⚠ Found {report['risk_count']} Privacy Risk(s):\n\n"
                for risk in report['privacy_risks']:
                    result_text += f"Risk Level: {risk['risk']}\n"
                    result_text += f"Type: {risk['type']}\n"
                    result_text += f"{risk['description']}\n"
                    result_text += f"Recommendation: {risk['recommendation']}\n\n"
            else:
                result_text += f"✅ No privacy risks detected\n"
            
            self.privacy_results.setText(result_text)
            self.log("Privacy analysis completed", "success")
            
            if self.privacy_strip_check.isChecked():
                output_path = self.privacy_image_path.replace('.png', '_clean.png')
                try:
                    clean_image = self.engine.strip_metadata(self.privacy_image_path, output_path)
                    result_text += f"\n{'='*50}\n"
                    result_text += f"✅ Metadata stripped\n"
                    result_text += f"Cleaned image saved to: {clean_image}\n"
                    self.privacy_results.setText(result_text)
                    self.log(f"Metadata stripped and saved to {clean_image}", "success")
                    QMessageBox.information(self, "Success", f"Metadata stripped successfully!\n\nSaved to: {clean_image}")
                except Exception as e:
                    self.log(f"Failed to strip metadata: {e}", "error")
                    QMessageBox.critical(self, "Error", f"Failed to strip metadata: {str(e)}")
        except Exception as e:
            self.log(f"Privacy analysis failed: {e}", "error")
            QMessageBox.critical(self, "Error", f"Privacy analysis failed:\n{str(e)}")
    
    def create_archive_tab(self) -> QWidget:
        """Create the archive embed tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Input files/folders
        input_group = QGroupBox("Files/Folders to Embed")
        input_layout = QVBoxLayout()
        self.archive_files_list = QTextEdit()
        self.archive_files_list.setMaximumHeight(100)
        self.archive_files_list.setPlaceholderText("Selected files/folders will appear here...")
        input_layout.addWidget(self.archive_files_list)
        
        buttons_layout = QHBoxLayout()
        add_files_btn = QPushButton("Add Files")
        add_files_btn.clicked.connect(self.select_archive_files)
        add_folder_btn = QPushButton("Add Folder")
        add_folder_btn.clicked.connect(self.select_archive_folder)
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(lambda: self.archive_files_list.clear())
        buttons_layout.addWidget(add_files_btn)
        buttons_layout.addWidget(add_folder_btn)
        buttons_layout.addWidget(clear_btn)
        input_layout.addLayout(buttons_layout)
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Cover image
        cover_group = QGroupBox("Cover Image (Optional)")
        cover_layout = QVBoxLayout()
        self.archive_cover_label = QLabel("No cover image (will create new)")
        archive_cover_btn = QPushButton("Select Cover Image")
        archive_cover_btn.clicked.connect(self.select_archive_cover)
        cover_layout.addWidget(self.archive_cover_label)
        cover_layout.addWidget(archive_cover_btn)
        cover_group.setLayout(cover_layout)
        layout.addWidget(cover_group)
        
        # Password
        password_group = QGroupBox("Password (Optional)")
        password_layout = QVBoxLayout()
        self.archive_password_input = QLineEdit()
        self.archive_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        password_layout.addWidget(self.archive_password_input)
        password_group.setLayout(password_layout)
        layout.addWidget(password_group)
        
        # Options
        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout()
        self.archive_compress_check = QCheckBox("Compress archive")
        self.archive_compress_check.setChecked(True)
        self.archive_robustness_check = QCheckBox("Enable social media robustness")
        self.archive_anti_steganalysis_check = QCheckBox("Enable anti-steganalysis protection")
        self.archive_strip_metadata_check = QCheckBox("Strip metadata")
        options_layout.addWidget(self.archive_compress_check)
        options_layout.addWidget(self.archive_robustness_check)
        options_layout.addWidget(self.archive_anti_steganalysis_check)
        options_layout.addWidget(self.archive_strip_metadata_check)
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Output
        output_group = QGroupBox("Output Image")
        output_layout = QVBoxLayout()
        self.archive_output_label = QLabel("Will auto-generate filename")
        archive_output_btn = QPushButton("Choose Output File")
        archive_output_btn.clicked.connect(self.select_archive_output)
        output_layout.addWidget(self.archive_output_label)
        output_layout.addWidget(archive_output_btn)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        # Embed button
        embed_btn = QPushButton("Embed Archive")
        embed_btn.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold; padding: 10px;")
        embed_btn.clicked.connect(self.embed_archive)
        layout.addWidget(embed_btn)
        
        layout.addStretch()
        
        self.archive_file_paths = []
        self.archive_cover_path = None
        self.archive_output_path = None
        
        return widget
    
    def create_extract_archive_tab(self) -> QWidget:
        """Create the extract archive tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Stego image
        image_group = QGroupBox("Stego Image")
        image_layout = QVBoxLayout()
        self.archive_stego_label = QLabel("No image selected")
        archive_image_btn = QPushButton("Select Stego Image")
        archive_image_btn.clicked.connect(self.select_archive_stego_image)
        image_layout.addWidget(self.archive_stego_label)
        image_layout.addWidget(archive_image_btn)
        image_group.setLayout(image_layout)
        layout.addWidget(image_group)
        
        # Password
        password_group = QGroupBox("Password (if encrypted)")
        password_layout = QVBoxLayout()
        self.archive_extract_password = QLineEdit()
        self.archive_extract_password.setEchoMode(QLineEdit.EchoMode.Password)
        password_layout.addWidget(self.archive_extract_password)
        password_group.setLayout(password_layout)
        layout.addWidget(password_group)
        
        # Robustness
        self.archive_extract_robustness = QCheckBox("Enable robustness recovery")
        layout.addWidget(self.archive_extract_robustness)
        
        # Output directory
        output_group = QGroupBox("Extract To")
        output_layout = QVBoxLayout()
        self.archive_extract_output_label = QLabel("Will extract to current directory")
        archive_extract_dir_btn = QPushButton("Choose Directory")
        archive_extract_dir_btn.clicked.connect(self.select_archive_extract_dir)
        output_layout.addWidget(self.archive_extract_output_label)
        output_layout.addWidget(archive_extract_dir_btn)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        # Extract button
        extract_btn = QPushButton("Extract Archive")
        extract_btn.setStyleSheet("background-color: #2196F3; color: white; font-weight: bold; padding: 10px;")
        extract_btn.clicked.connect(self.extract_archive)
        layout.addWidget(extract_btn)
        
        layout.addStretch()
        
        self.archive_extract_image_path = None
        self.archive_extract_output_dir = '.'
        
        return widget
    
    def create_capacity_tab(self) -> QWidget:
        """Create the capacity calculator tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Image selection
        image_group = QGroupBox("Cover Image")
        image_layout = QVBoxLayout()
        self.capacity_image_label = QLabel("No image selected")
        capacity_image_btn = QPushButton("Select Image")
        capacity_image_btn.clicked.connect(self.select_capacity_image)
        image_layout.addWidget(self.capacity_image_label)
        image_layout.addWidget(capacity_image_btn)
        image_group.setLayout(image_layout)
        layout.addWidget(image_group)
        
        # Mode
        mode_group = QGroupBox("Mode")
        mode_layout = QVBoxLayout()
        self.capacity_mode_combo = QComboBox()
        self.capacity_mode_combo.addItems(['lsb', 'pixel'])
        mode_layout.addWidget(self.capacity_mode_combo)
        mode_group.setLayout(mode_layout)
        layout.addWidget(mode_group)
        
        # Options
        self.capacity_compress_check = QCheckBox("Account for compression")
        layout.addWidget(self.capacity_compress_check)
        
        # File to check (optional)
        file_group = QGroupBox("Check File Fit (Optional)")
        file_layout = QVBoxLayout()
        self.capacity_file_label = QLabel("No file selected")
        capacity_file_btn = QPushButton("Select File to Check")
        capacity_file_btn.clicked.connect(self.select_capacity_file)
        file_layout.addWidget(self.capacity_file_label)
        file_layout.addWidget(capacity_file_btn)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Calculate button
        calc_btn = QPushButton("Calculate Capacity")
        calc_btn.setStyleSheet("background-color: #FF9800; color: white; font-weight: bold; padding: 10px;")
        calc_btn.clicked.connect(self.calculate_capacity)
        layout.addWidget(calc_btn)
        
        # Results display
        self.capacity_results = QTextEdit()
        self.capacity_results.setReadOnly(True)
        layout.addWidget(self.capacity_results)
        
        self.capacity_image_path = None
        self.capacity_file_path = None
        
        return widget
    
    def create_detect_tab(self) -> QWidget:
        """Create the steganalysis detection tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Image selection
        image_group = QGroupBox("Image to Analyze")
        image_layout = QVBoxLayout()
        self.detect_image_label = QLabel("No image selected")
        detect_image_btn = QPushButton("Select Image")
        detect_image_btn.clicked.connect(self.select_detect_image)
        image_layout.addWidget(self.detect_image_label)
        image_layout.addWidget(detect_image_btn)
        image_group.setLayout(image_layout)
        layout.addWidget(image_group)
        
        # Detect button
        detect_btn = QPushButton("Detect Steganography")
        detect_btn.setStyleSheet("background-color: #9C27B0; color: white; font-weight: bold; padding: 10px;")
        detect_btn.clicked.connect(self.detect_steganography)
        layout.addWidget(detect_btn)
        
        # Results display
        self.detect_results = QTextEdit()
        self.detect_results.setReadOnly(True)
        layout.addWidget(self.detect_results)
        
        self.detect_image_path = None
        
        return widget
    
    def create_privacy_tab(self) -> QWidget:
        """Create the privacy analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Image selection
        image_group = QGroupBox("Image to Analyze")
        image_layout = QVBoxLayout()
        self.privacy_image_label = QLabel("No image selected")
        privacy_image_btn = QPushButton("Select Image")
        privacy_image_btn.clicked.connect(self.select_privacy_image)
        image_layout.addWidget(self.privacy_image_label)
        image_layout.addWidget(privacy_image_btn)
        image_group.setLayout(image_layout)
        layout.addWidget(image_group)
        
        # Options
        self.privacy_strip_check = QCheckBox("Strip metadata and save cleaned image")
        layout.addWidget(self.privacy_strip_check)
        
        # Analyze button
        analyze_btn = QPushButton("Analyze Privacy")
        analyze_btn.setStyleSheet("background-color: #F44336; color: white; font-weight: bold; padding: 10px;")
        analyze_btn.clicked.connect(self.analyze_privacy)
        layout.addWidget(analyze_btn)
        
        # Results display
        self.privacy_results = QTextEdit()
        self.privacy_results.setReadOnly(True)
        layout.addWidget(self.privacy_results)
        
        self.privacy_image_path = None
        
        return widget
    
    # Archive tab handlers
    def select_archive_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files", "", "All Files (*.*)")
        if files:
            self.archive_file_paths.extend(files)
            self.archive_files_list.append('\n'.join([os.path.basename(f) for f in files]))
    
    def select_archive_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder:
            self.archive_file_paths.append(folder)
            self.archive_files_list.append(f"📁 {os.path.basename(folder)}")
    
    def select_archive_cover(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Cover Image", "", "Images (*.png *.jpg *.jpeg *.bmp *.tiff *.gif)"
        )
        if file_path:
            self.archive_cover_path = file_path
            self.archive_cover_label.setText(f"Cover: {os.path.basename(file_path)}")
        else:
            self.archive_cover_path = None
            self.archive_cover_label.setText("No cover image (will create new)")
    
    def select_archive_output(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Output Image", "", "PNG Images (*.png)"
        )
        if file_path:
            self.archive_output_path = file_path
            self.archive_output_label.setText(f"Output: {os.path.basename(file_path)}")
    
    def embed_archive(self):
        if not self.archive_file_paths:
            QMessageBox.warning(self, "Error", "Please select files or folders to embed")
            return
        
        password_text = self.archive_password_input.text()
        password = password_text.strip() if password_text else None
        
        if not self.archive_output_path:
            base_name = "archive"
            output_dir = os.path.dirname(self.archive_file_paths[0]) if self.archive_file_paths else '.'
            self.archive_output_path = os.path.join(output_dir, f"{base_name}_stego.png")
        
        self.log(f"Embedding archive with {len(self.archive_file_paths)} item(s)...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        self.worker = StegoWorker(
            'embed-archive',
            file_paths=self.archive_file_paths,
            cover_image=self.archive_cover_path,
            output_image=self.archive_output_path,
            password=password,
            compress=self.archive_compress_check.isChecked(),
            robustness=self.archive_robustness_check.isChecked(),
            anti_steganalysis=self.archive_anti_steganalysis_check.isChecked(),
            strip_metadata=self.archive_strip_metadata_check.isChecked()
        )
        self.worker.finished.connect(self.on_embed_finished)
        self.worker.message.connect(self.log)
        self.worker.start()
    
    def select_archive_stego_image(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Stego Image", "", "PNG Images (*.png)"
        )
        if file_path:
            self.archive_extract_image_path = file_path
            self.archive_stego_label.setText(f"Image: {os.path.basename(file_path)}")
    
    def select_archive_extract_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Choose Directory")
        if dir_path:
            self.archive_extract_output_dir = dir_path
            self.archive_extract_output_label.setText(f"Output directory: {dir_path}")
    
    def extract_archive(self):
        if not self.archive_extract_image_path:
            QMessageBox.warning(self, "Error", "Please select a stego image")
            return
        
        password_text = self.archive_extract_password.text()
        password = password_text.strip() if password_text else None
        
        self.log(f"Extracting archive from: {os.path.basename(self.archive_extract_image_path)}")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        self.worker = StegoWorker(
            'extract-archive',
            stego_image=self.archive_extract_image_path,
            output_dir=self.archive_extract_output_dir,
            password=password,
            robustness=self.archive_extract_robustness.isChecked()
        )
        self.worker.finished.connect(self.on_extract_archive_finished)
        self.worker.message.connect(self.log)
        self.worker.start()
    
    def on_extract_archive_finished(self, success: bool, result_data: str):
        self.progress_bar.setVisible(False)
        if success:
            QMessageBox.information(self, "Success", f"Archive extracted successfully!\n\nOutput: {self.archive_extract_output_dir}")
        else:
            QMessageBox.critical(self, "Error", "Failed to extract archive. Check the log for details.")
    
    # Capacity tab handlers
    def select_capacity_image(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Cover Image", "", "Images (*.png *.jpg *.jpeg *.bmp *.tiff *.gif)"
        )
        if file_path:
            self.capacity_image_path = file_path
            self.capacity_image_label.setText(f"Image: {os.path.basename(file_path)}")
    
    def select_capacity_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Check", "", "All Files (*.*)")
        if file_path:
            self.capacity_file_path = file_path
            self.capacity_file_label.setText(f"File: {os.path.basename(file_path)}")
    
    def calculate_capacity(self):
        if not self.capacity_image_path:
            QMessageBox.warning(self, "Error", "Please select a cover image")
            return
        
        mode = self.capacity_mode_combo.currentText()
        compress = self.capacity_compress_check.isChecked()
        
        capacity = self.engine.get_capacity_info(cover_image=self.capacity_image_path, mode=mode)
        
        result_text = f"📊 Capacity Analysis\n{'='*50}\n\n"
        result_text += f"Image: {os.path.basename(self.capacity_image_path)}\n"
        result_text += f"Size: {capacity['image_size'][0]}x{capacity['image_size'][1]} pixels\n"
        result_text += f"Mode: {capacity['mode']}\n\n"
        result_text += f"Capacity:\n"
        result_text += f"  Maximum: {capacity['max_kb']:.2f} KB ({capacity['max_mb']:.3f} MB)\n"
        if compress:
            result_text += f"  With Compression: {capacity['max_kb_compressed']:.2f} KB ({capacity['max_mb_compressed']:.3f} MB)\n"
        
        result_text += f"\nRecommendations:\n"
        for rec in capacity['recommendations']:
            result_text += f"  • {rec}\n"
        
        if self.capacity_file_path:
            fit_analysis = self.engine.check_file_fits(
                self.capacity_file_path, cover_image=self.capacity_image_path,
                mode=mode, compress=compress
            )
            result_text += f"\n{'='*50}\n"
            result_text += f"File Fit Analysis:\n"
            result_text += f"  File: {os.path.basename(self.capacity_file_path)}\n"
            result_text += f"  Size: {self.engine.capacity.format_size(fit_analysis['file_size'])}\n"
            result_text += f"  Fits: {'✅ Yes' if fit_analysis['fits'] else '❌ No'}\n"
            result_text += f"  Utilization: {fit_analysis['utilization_percent']:.1f}%\n"
            
            if fit_analysis['warnings']:
                result_text += f"\n⚠ Warnings:\n"
                for warning in fit_analysis['warnings']:
                    result_text += f"  • {warning}\n"
            
            if fit_analysis['recommendations']:
                result_text += f"\n💡 Recommendations:\n"
                for rec in fit_analysis['recommendations']:
                    result_text += f"  • {rec}\n"
        
        self.capacity_results.setText(result_text)
    
    # Detect tab handlers
    def select_detect_image(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Image", "", "PNG Images (*.png)"
        )
        if file_path:
            self.detect_image_path = file_path
            self.detect_image_label.setText(f"Image: {os.path.basename(file_path)}")
    
    def detect_steganography(self):
        if not self.detect_image_path:
            QMessageBox.warning(self, "Error", "Please select an image")
            return
        
        detection = self.engine.detect_steganography(self.detect_image_path)
        
        if 'error' in detection:
            self.detect_results.setText(f"Error: {detection['error']}")
            return
        
        result_text = f"🔍 Steganography Detection Results\n{'='*50}\n\n"
        result_text += f"Image: {os.path.basename(self.detect_image_path)}\n\n"
        result_text += f"Risk Score: {detection['risk_score']}/100\n"
        result_text += f"Risk Level: {detection['risk_level']}\n"
        result_text += f"Detected: {'⚠️ Yes' if detection['detected'] else '✅ No'}\n\n"
        
        result_text += f"LSB Analysis:\n"
        lsb = detection['lsb_analysis']
        result_text += f"  Transition Rate: {lsb['transition_rate']:.3f}\n"
        result_text += f"  Suspicious Patterns: {lsb['suspicious_patterns']:.3f}\n\n"
        
        result_text += f"Histogram Analysis:\n"
        hist = detection['histogram_analysis']
        result_text += f"  Anomaly Score: {hist['anomaly_score']:.3f}\n"
        result_text += f"  Anomalies Detected: {'Yes' if hist['anomalies_detected'] else 'No'}\n\n"
        
        result_text += f"RS Analysis:\n"
        rs = detection['rs_analysis']
        result_text += f"  Detected: {'Yes' if rs['detected'] else 'No'}\n"
        result_text += f"  Imbalance: {rs['imbalance']:.3f}\n"
        
        self.detect_results.setText(result_text)
    
    # Privacy tab handlers
    def select_privacy_image(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Image", "", "PNG Images (*.png)"
        )
        if file_path:
            self.privacy_image_path = file_path
            self.privacy_image_label.setText(f"Image: {os.path.basename(file_path)}")
    
    def analyze_privacy(self):
        if not self.privacy_image_path:
            QMessageBox.warning(self, "Error", "Please select an image")
            return
        
        report = self.engine.get_privacy_report(self.privacy_image_path)
        
        result_text = f"🔒 Privacy Analysis\n{'='*50}\n\n"
        result_text += f"Image: {os.path.basename(self.privacy_image_path)}\n"
        result_text += f"File Size: {self.engine.capacity.format_size(report['metadata']['file_size'])}\n\n"
        
        if report['metadata']['has_exif']:
            result_text += f"⚠ EXIF Data Found\n"
            result_text += f"  Tags: {len(report['metadata']['exif'])}\n\n"
        
        if report['metadata']['has_gps']:
            result_text += f"⚠⚠ GPS Location Data Found!\n"
            result_text += f"  This reveals where the photo was taken\n\n"
        
        if report['privacy_risks']:
            result_text += f"⚠ Found {report['risk_count']} Privacy Risk(s):\n\n"
            for risk in report['privacy_risks']:
                result_text += f"Risk Level: {risk['risk']}\n"
                result_text += f"Type: {risk['type']}\n"
                result_text += f"{risk['description']}\n"
                result_text += f"Recommendation: {risk['recommendation']}\n\n"
        else:
            result_text += f"✅ No privacy risks detected\n"
        
        self.privacy_results.setText(result_text)
        
        if self.privacy_strip_check.isChecked():
            output_path = self.privacy_image_path.replace('.png', '_clean.png')
            try:
                clean_image = self.engine.strip_metadata(self.privacy_image_path, output_path)
                result_text += f"\n{'='*50}\n"
                result_text += f"✅ Metadata stripped\n"
                result_text += f"Cleaned image saved to: {clean_image}\n"
                self.privacy_results.setText(result_text)
                QMessageBox.information(self, "Success", f"Metadata stripped successfully!\n\nSaved to: {clean_image}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to strip metadata: {str(e)}")


def main():
    """Launch GUI application"""
    if not PYQT6_AVAILABLE:
        print("PyQt6 is required for the GUI. Install it with: pip install PyQt6")
        sys.exit(1)
    
    app = QApplication(sys.argv)
    window = StegoVaultGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()

