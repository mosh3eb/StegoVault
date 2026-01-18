"""
Main GUI window for StegoVault
"""

import sys
import os
from pathlib import Path
from typing import Optional

try:
    from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                 QHBoxLayout, QPushButton, QLabel, QFileDialog,
                                 QTextEdit, QProgressBar, QGroupBox, QLineEdit,
                                 QCheckBox, QComboBox, QMessageBox, QTabWidget)
    from PyQt6.QtCore import Qt, QThread, pyqtSignal
    from PyQt6.QtGui import QIcon, QFont
    PYQT6_AVAILABLE = True
except ImportError:
    PYQT6_AVAILABLE = False

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

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
            engine = StegoEngine()
            
            if self.operation == 'embed':
                try:
                    # Verify file exists
                    import os
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
                        show_progress=False
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
                    import traceback
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
                    self.message.emit("Failed to extract file")
                    self.finished.emit(False, '')
        
        except Exception as e:
            import traceback
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
        self.engine = StegoEngine()
        self.worker: Optional[StegoWorker] = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize the UI"""
        self.setWindowTitle("StegoVault - Advanced Steganography Tool")
        self.setGeometry(100, 100, 800, 600)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        
        tabs = QTabWidget()
        main_layout.addWidget(tabs)
        
        embed_tab = self.create_embed_tab()
        tabs.addTab(embed_tab, "Embed File")
        
        extract_tab = self.create_extract_tab()
        tabs.addTab(extract_tab, "Extract File")
        
        info_tab = self.create_info_tab()
        tabs.addTab(info_tab, "View Info")
        
        self.statusBar().showMessage("Ready")
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)
        
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setMaximumHeight(150)
        main_layout.addWidget(self.log_area)
    
    def create_embed_tab(self) -> QWidget:
        """Create the embed tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Input file
        input_group = QGroupBox("File to Embed")
        input_layout = QVBoxLayout()
        self.input_file_label = QLabel("No file selected")
        input_btn = QPushButton("Select File")
        input_btn.clicked.connect(self.select_input_file)
        input_layout.addWidget(self.input_file_label)
        input_layout.addWidget(input_btn)
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Cover image
        cover_group = QGroupBox("Cover Image (Optional)")
        cover_layout = QVBoxLayout()
        self.cover_image_label = QLabel("No cover image (will create new)")
        cover_btn = QPushButton("Select Cover Image")
        cover_btn.clicked.connect(self.select_cover_image)
        cover_layout.addWidget(self.cover_image_label)
        cover_layout.addWidget(cover_btn)
        cover_group.setLayout(cover_layout)
        layout.addWidget(cover_group)
        
        # Password
        password_group = QGroupBox("Password (Optional)")
        password_layout = QVBoxLayout()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        password_layout.addWidget(self.password_input)
        password_group.setLayout(password_layout)
        layout.addWidget(password_group)
        
        # Mode
        mode_group = QGroupBox("Mode")
        mode_layout = QVBoxLayout()
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(['pixel', 'lsb'])
        mode_layout.addWidget(self.mode_combo)
        mode_group.setLayout(mode_layout)
        layout.addWidget(mode_group)
        
        # Compression
        self.compress_check = QCheckBox("Compress data")
        layout.addWidget(self.compress_check)
        
        # Output file
        output_group = QGroupBox("Output Image")
        output_layout = QVBoxLayout()
        self.output_file_label = QLabel("Will auto-generate filename")
        output_btn = QPushButton("Choose Output File")
        output_btn.clicked.connect(self.select_output_file)
        output_layout.addWidget(self.output_file_label)
        output_layout.addWidget(output_btn)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
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
    
    def log(self, message: str):
        """Add message to log area"""
        self.log_area.append(message)
        self.statusBar().showMessage(message)
    
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
            self, "Select Cover Image", "", "Images (*.png *.jpg *.jpeg *.bmp *.tiff)"
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
            self, "Save Output Image", "", "PNG Images (*.png);;JPEG Images (*.jpg)"
        )
        if file_path:
            self.output_file_path = file_path
            self.output_file_label.setText(f"Output: {os.path.basename(file_path)}")
    
    def select_stego_image(self):
        """Select stego image"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Stego Image", "", "Images (*.png *.jpg *.jpeg *.bmp *.tiff)"
        )
        if file_path:
            self.stego_image_path = file_path
            self.stego_image_label.setText(f"Image: {os.path.basename(file_path)}")
    
    def select_info_image(self):
        """Select image for info"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Image", "", "Images (*.png *.jpg *.jpeg *.bmp *.tiff)"
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
        
        self.log(f"Embedding file: {os.path.basename(self.input_file_path)}")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        self.worker = StegoWorker(
            'embed',
            input_file=self.input_file_path,
            cover_image=self.cover_image_path,
            output_image=self.output_file_path,
            password=password,
            mode=mode,
            compress=compress
        )
        self.worker.finished.connect(self.on_embed_finished)
        self.worker.message.connect(self.log)
        self.worker.start()
    
    def extract_file(self):
        """Extract file"""
        if not self.stego_image_path:
            QMessageBox.warning(self, "Error", "Please select a stego image")
            return
        
        password_text = self.extract_password_input.text()
        # Get password exactly as entered, only strip if not empty
        password = password_text.strip() if password_text else None
        
        self.log(f"Extracting from: {os.path.basename(self.stego_image_path)}")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
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
        """Handle embed completion"""
        self.progress_bar.setVisible(False)
        if success:
            QMessageBox.information(self, "Success", f"File embedded successfully!\n\nOutput: {output_path}")
        else:
            # Get the last error message from log
            log_text = self.log_area.toPlainText()
            error_lines = [line for line in log_text.split('\n') if 'Error' in line or 'Failed' in line or 'Permission' in line or 'not found' in line.lower()]
            if error_lines:
                # Get the most recent error message (usually the most specific one)
                error_msg = error_lines[-1] if error_lines else "Failed to embed file"
                # Remove "Failed to embed file:" prefix if present to avoid duplication
                if error_msg.startswith("Failed to embed file:"):
                    error_msg = error_msg.replace("Failed to embed file:", "").strip()
            else:
                error_msg = "Failed to embed file"
            
            QMessageBox.critical(self, "Error", f"Failed to embed file.\n\n{error_msg}\n\nCheck the log area below for more details.")
    
    def on_extract_finished(self, success: bool, extracted_path: str):
        """Handle extract completion"""
        self.progress_bar.setVisible(False)
        if success:
            QMessageBox.information(self, "Success", f"File extracted successfully!\n\nOutput: {extracted_path}")
        else:
            QMessageBox.critical(self, "Error", "Failed to extract file. Check the log for details.")


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

