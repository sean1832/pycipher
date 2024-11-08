import base64
import os
import sys

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from cipher import __version__

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from cipher.cipher import Cipher


class CipherApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"Cipher {__version__}")
        text_font = QFont("Consolas", 10)  # better for monospace font

        # Central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)

        # Encryption Method Selection
        method_layout = QHBoxLayout()
        self.method_label = QLabel("Method:")
        self.method = QComboBox()
        self.method.addItems(["AES-GCM", "Legacy"])
        method_layout.addWidget(self.method_label)
        method_layout.addWidget(self.method)
        main_layout.addLayout(method_layout)

        # Input Type Selection
        input_type_layout = QHBoxLayout()
        self.input_type_label = QLabel("Input Type:")
        self.input_type = QComboBox()
        self.input_type.addItems(["String", "File"])
        self.input_type.currentIndexChanged.connect(self.toggle_input_fields)
        input_type_layout.addWidget(self.input_type_label)
        input_type_layout.addWidget(self.input_type)
        main_layout.addLayout(input_type_layout)

        # Input File Selection
        self.input_file_layout = QHBoxLayout()
        self.input_file_path = QLineEdit()
        self.input_file_button = QPushButton("Browse")
        self.input_file_button.clicked.connect(self.select_input_file)
        self.input_file_layout.addWidget(self.input_file_path)
        self.input_file_layout.addWidget(self.input_file_button)
        main_layout.addLayout(self.input_file_layout)

        # Input Text Field
        self.input_text = QTextEdit()
        main_layout.addWidget(self.input_text)
        self.input_text.setFont(text_font)

        # Output Type Selection
        output_type_layout = QHBoxLayout()
        self.output_type_label = QLabel("Output Type:")
        self.output_type = QComboBox()
        self.output_type.addItems(["String", "File"])
        self.output_type.currentIndexChanged.connect(self.toggle_output_fields)
        output_type_layout.addWidget(self.output_type_label)
        output_type_layout.addWidget(self.output_type)
        main_layout.addLayout(output_type_layout)

        # Output File Selection
        self.output_file_layout = QHBoxLayout()
        self.output_file_path = QLineEdit()
        self.output_file_button = QPushButton("Browse")
        self.output_file_button.clicked.connect(self.select_output_file)
        self.output_file_layout.addWidget(self.output_file_path)
        self.output_file_layout.addWidget(self.output_file_button)
        main_layout.addLayout(self.output_file_layout)

        # Key Entry
        self.key_label = QLabel("Password:")
        self.key_input = QLineEdit()
        self.key_input.setEchoMode(QLineEdit.EchoMode.Password)
        main_layout.addWidget(self.key_label, alignment=Qt.AlignmentFlag.AlignTop)
        main_layout.addWidget(self.key_input, alignment=Qt.AlignmentFlag.AlignBottom)

        # Encryption and Decryption Buttons
        button_layout = QHBoxLayout()
        self.encrypt_button = QPushButton("Encrypt")
        self.encrypt_button.clicked.connect(self.encrypt)
        self.decrypt_button = QPushButton("Decrypt")
        self.decrypt_button.clicked.connect(self.decrypt)
        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)
        main_layout.addLayout(button_layout)

        # Output Text Field
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        main_layout.addWidget(self.output_text)
        self.output_text.setFont(text_font)

        # Initially set visibility of input/output fields
        self.toggle_input_fields()
        self.toggle_output_fields()

    def toggle_input_fields(self):
        input_type = self.input_type.currentText()
        if input_type == "File":
            self.input_file_layout.itemAt(0).widget().setVisible(True)  # type: ignore # QLineEdit
            self.input_file_layout.itemAt(1).widget().setVisible(True)  # type: ignore # QPushButton
            self.input_text.setVisible(False)
        else:
            self.input_file_layout.itemAt(0).widget().setVisible(False)  # type: ignore
            self.input_file_layout.itemAt(1).widget().setVisible(False)  # type: ignore
            self.input_text.setVisible(True)

        # Adjust the window size based on the new layout
        self.adjustSize()

    def toggle_output_fields(self):
        output_type = self.output_type.currentText()
        if output_type == "File":
            self.output_file_layout.itemAt(0).widget().setVisible(True)  # type: ignore # QLineEdit
            self.output_file_layout.itemAt(1).widget().setVisible(True)  # type: ignore # QPushButton
            self.output_text.setVisible(False)
        else:
            self.output_file_layout.itemAt(0).widget().setVisible(False)  # type: ignore
            self.output_file_layout.itemAt(1).widget().setVisible(False)  # type: ignore
            self.output_text.setVisible(True)

        # Adjust the window size based on the new layout
        self.adjustSize()

    def select_input_file(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Select Input File")
        if file_path:
            self.input_file_path.setText(file_path)

    def select_output_file(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getSaveFileName(self, "Select Output File")
        if file_path:
            self.output_file_path.setText(file_path)

    def encrypt(self):
        key_text = self.key_input.text()
        if not key_text:
            QMessageBox.warning(self, "Error", "Please enter a password.")
            return

        key = key_text.encode("utf-8")
        cipher = Cipher(key)

        # Get input data
        input_type = self.input_type.currentText()
        if input_type == "File":
            input_file = self.input_file_path.text()
            if not input_file:
                QMessageBox.warning(self, "Error", "Please select an input file.")
                return
            try:
                with open(input_file, "rb") as f:
                    data = f.read()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to read input file: {e}")
                return
        else:
            data = self.input_text.toPlainText().encode("utf-8")
            if not data:
                QMessageBox.warning(self, "Error", "Please enter text to encrypt.")
                return

        # Encrypt data
        try:
            if self.method.currentText() == "AES-GCM":
                encrypted_data = cipher.encrypt_aesgcm(data)
            else:
                encrypted_data = cipher.encrypt_legacy(data)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Encryption failed: {e}")
            return

        # Handle output
        output_type = self.output_type.currentText()
        if output_type == "File":
            output_file = self.output_file_path.text()
            if not output_file:
                QMessageBox.warning(self, "Error", "Please select an output file.")
                return
            try:
                with open(output_file, "wb") as f:
                    f.write(encrypted_data)
                QMessageBox.information(self, "Success", "Data encrypted and saved to file.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to write output file: {e}")
        else:
            self.output_text.setPlainText(base64.b64encode(encrypted_data).decode("utf-8"))

    def decrypt(self):
        key_text = self.key_input.text()
        if not key_text:
            QMessageBox.warning(self, "Error", "Please enter a password.")
            return

        key = key_text.encode("utf-8")
        cipher = Cipher(key)

        # Get input data
        input_type = self.input_type.currentText()
        if input_type == "File":
            input_file = self.input_file_path.text()
            if not input_file:
                QMessageBox.warning(self, "Error", "Please select an input file.")
                return
            try:
                with open(input_file, "rb") as f:
                    data = f.read()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to read input file: {e}")
                return
        else:
            input_text = self.input_text.toPlainText()
            if not input_text:
                QMessageBox.warning(self, "Error", "Please enter text to decrypt.")
                return
            try:
                data = base64.b64decode(input_text.encode("utf-8"))
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Invalid base64 input: {e}")
                return

        # Decrypt data
        try:
            if self.method.currentText() == "AES-GCM":
                decrypted_data = cipher.decrypt_aesgcm(data)
            else:
                decrypted_data = cipher.decrypt_legacy(data)
        except ValueError:
            QMessageBox.warning(self, "Error", "Incorrect password.")
            return
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Decryption failed: {e}")
            return

        # Handle output
        output_type = self.output_type.currentText()
        if output_type == "File":
            output_file = self.output_file_path.text()
            if not output_file:
                QMessageBox.warning(self, "Error", "Please select an output file.")
                return
            try:
                with open(output_file, "wb") as f:
                    f.write(decrypted_data)
                QMessageBox.information(self, "Success", "Data decrypted and saved to file.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to write output file: {e}")
        else:
            try:
                self.output_text.setPlainText(decrypted_data.decode("utf-8"))
            except UnicodeDecodeError:
                QMessageBox.warning(self, "Error", "Decrypted data is not valid UTF-8 text.")
                self.output_text.setPlainText("<Binary Data>")


def main():
    app = QApplication(sys.argv)
    window = CipherApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
