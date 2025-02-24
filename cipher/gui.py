import base64
import os
import sys

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QIcon
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
    QSizePolicy,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from cipher import ICON_PATH, __version__

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from cipher.cipher import KDF, Argon2Params, Cipher, Pbkdf2Params, ScryptParams


class CipherApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"Cipher {__version__}")
        self.setWindowIcon(QIcon(ICON_PATH))
        text_font = QFont("Consolas", 10)  # better for monospace font

        # Central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)

        # Encryption Method Selection
        encryption_setting_layout = QHBoxLayout()
        self.algorithm_label = QLabel("Algorithm:")
        self.algorithm = QComboBox()
        # Set the ComboBox to expand to full width
        self.algorithm.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        encryption_setting_layout.addWidget(self.algorithm_label)
        encryption_setting_layout.addWidget(self.algorithm)
        self.algorithm.addItems(["AES-GCM", "Legacy"])

        self.kdf_label = QLabel("KDF:")
        self.kdf = QComboBox()
        self.kdf.addItems(["PBKDF2", "Scrypt", "Argon2"])
        self.kdf.setCurrentIndex(2)
        # Set the ComboBox to expand to full width
        self.kdf.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        encryption_setting_layout.addWidget(self.kdf_label)
        encryption_setting_layout.addWidget(self.kdf)
        main_layout.addLayout(encryption_setting_layout)

        # KDF Parameter Widgets (will be shown/hidden based on selected KDF)
        self.kdf_param_layout = QHBoxLayout()

        # PBKDF2 parameters
        self.pbkdf2_iter_label = QLabel("Iterations:")
        self.pbkdf2_iter_input = QSpinBox()
        self.pbkdf2_iter_input.setRange(100_000, 1_000_000)
        self.pbkdf2_iter_input.setValue(300_000)
        self.pbkdf2_iter_input.setSingleStep(100_000)
        self.pbkdf2_iter_input.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        # Scrypt parameters
        self.scrypt_n_label = QLabel("Cost (N):")
        self.scrypt_n_input = QSpinBox()
        self.scrypt_n_input.setRange(16, 4096)  # 64 MiB to 4 GiB
        self.scrypt_n_input.setValue(16)  # 64 MiB
        self.scrypt_n_input.setSingleStep(16)
        self.scrypt_n_input.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.scrypt_r_label = QLabel("Block Size (r):")
        self.scrypt_r_input = QSpinBox()
        self.scrypt_r_input.setRange(8, 32)
        self.scrypt_r_input.setValue(8)
        self.scrypt_r_input.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.scrypt_p_label = QLabel("Parallelism (p):")
        self.scrypt_p_input = QSpinBox()
        self.scrypt_p_input.setRange(1, 16)
        self.scrypt_p_input.setValue(1)
        self.scrypt_p_input.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        # Argon2 parameters
        self.argon2_time_label = QLabel("Time Cost:")
        self.argon2_time_input = QSpinBox()
        self.argon2_time_input.setRange(1, 10)
        self.argon2_time_input.setValue(2)
        self.argon2_time_input.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.argon2_memory_label = QLabel("Memory (MB):")
        self.argon2_memory_input = QSpinBox()
        self.argon2_memory_input.setRange(64, 4096)  # 64 MiB to 4 GiB
        self.argon2_memory_input.setValue(1024)  # 1 GiB
        self.argon2_memory_input.setSingleStep(64)
        self.argon2_memory_input.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        self.argon2_parallelism_label = QLabel("Parallelism:")
        self.argon2_parallelism_input = QSpinBox()
        self.argon2_parallelism_input.setRange(1, 8)
        self.argon2_parallelism_input.setValue(4)
        self.argon2_parallelism_input.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )

        # Add KDF parameter layout to main layout
        main_layout.addLayout(self.kdf_param_layout)

        # Connect KDF selection change to update parameters
        self.kdf.currentIndexChanged.connect(self.update_kdf_parameters)
        self.update_kdf_parameters()  # Initialize parameter widgets

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

    def update_kdf_parameters(self):
        # Clear current parameter widgets without deleting them
        while self.kdf_param_layout.count():
            item = self.kdf_param_layout.takeAt(0)
            if item is None:
                break
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.hide()

        kdf = self.kdf.currentText()
        if kdf == "PBKDF2":
            self.kdf_param_layout.addWidget(self.pbkdf2_iter_label)
            self.pbkdf2_iter_label.show()
            self.kdf_param_layout.addWidget(self.pbkdf2_iter_input)
            self.pbkdf2_iter_input.show()
        elif kdf == "Scrypt":
            self.kdf_param_layout.addWidget(self.scrypt_n_label)
            self.scrypt_n_label.show()
            self.kdf_param_layout.addWidget(self.scrypt_n_input)
            self.scrypt_n_input.show()
            self.kdf_param_layout.addWidget(self.scrypt_r_label)
            self.scrypt_r_label.show()
            self.kdf_param_layout.addWidget(self.scrypt_r_input)
            self.scrypt_r_input.show()
            self.kdf_param_layout.addWidget(self.scrypt_p_label)
            self.scrypt_p_label.show()
            self.kdf_param_layout.addWidget(self.scrypt_p_input)
            self.scrypt_p_input.show()
        elif kdf == "Argon2":
            self.kdf_param_layout.addWidget(self.argon2_time_label)
            self.argon2_time_label.show()
            self.kdf_param_layout.addWidget(self.argon2_time_input)
            self.argon2_time_input.show()
            self.kdf_param_layout.addWidget(self.argon2_memory_label)
            self.argon2_memory_label.show()
            self.kdf_param_layout.addWidget(self.argon2_memory_input)
            self.argon2_memory_input.show()
            self.kdf_param_layout.addWidget(self.argon2_parallelism_label)
            self.argon2_parallelism_label.show()
            self.kdf_param_layout.addWidget(self.argon2_parallelism_input)
            self.argon2_parallelism_input.show()

    def update_window_size(self):
        # Force the main window to resize based on the current layout's size hint.
        # This ensures that if widgets are hidden (e.g., in File mode), the window becomes compact.
        self.adjustSize()  # Recalculate the layout
        self.resize(self.sizeHint())  # Enforce the new size

    def toggle_input_fields(self):
        input_type = self.input_type.currentText()
        if input_type == "File":
            self.input_file_layout.itemAt(0).widget().setVisible(True)  # type: ignore # QLineEdit
            self.input_file_layout.itemAt(1).widget().setVisible(True)  # type: ignore # QPushButton
            self.input_text.setVisible(False)
            self.setMinimumHeight(250)  # Smaller minimum height for file mode
        else:
            self.input_file_layout.itemAt(0).widget().setVisible(False)  # type: ignore
            self.input_file_layout.itemAt(1).widget().setVisible(False)  # type: ignore
            self.input_text.setVisible(True)
            self.setMinimumHeight(400)  # Larger minimum height for text mode

        # Adjust the window size based on the new layout
        self.update_window_size()

    def toggle_output_fields(self):
        output_type = self.output_type.currentText()
        if output_type == "File":
            self.output_file_layout.itemAt(0).widget().setVisible(True)  # type: ignore # QLineEdit
            self.output_file_layout.itemAt(1).widget().setVisible(True)  # type: ignore # QPushButton
            self.output_text.setVisible(False)
            self.setMinimumHeight(200)  # Smaller minimum height for file mode
        else:
            self.output_file_layout.itemAt(0).widget().setVisible(False)  # type: ignore
            self.output_file_layout.itemAt(1).widget().setVisible(False)  # type: ignore
            self.output_text.setVisible(True)
            self.setMinimumHeight(400)  # Larger minimum height for text mode

        # Adjust the window size based on the new layout
        self.update_window_size()

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

        kdf_params = {}
        if self.kdf.currentText() == "Scrypt":
            n = self.scrypt_n_input.value() * 1024  # convert to KB
            r = self.scrypt_r_input.value()
            p = self.scrypt_p_input.value()
            params = ScryptParams(n, r, p)
        elif self.kdf.currentText() == "Argon2":
            time_cost = self.argon2_time_input.value()
            memory_cost = self.argon2_memory_input.value() * 1024  # convert to KB
            parallelism = self.argon2_parallelism_input.value()
            params = Argon2Params(time_cost, memory_cost, parallelism)
        elif self.kdf.currentText() == "PBKDF2":
            iterations = self.pbkdf2_iter_input.value()
            params = Pbkdf2Params(iterations)

        key = key_text.encode("utf-8")
        cipher = Cipher(key, kdf=KDF(params, 32, **kdf_params))

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
            if self.algorithm.currentText() == "AES-GCM":
                encrypted_data = cipher.encrypt_aesgcm(data)
            else:
                encrypted_data = cipher.encrypt_legacy(data)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Encryption failed: {e}")
            return

        # prepend params to encrypted data
        encrypted_data = params.to_bytes() + encrypted_data

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

        # Get input data
        input_type = self.input_type.currentText()
        if input_type == "File":
            input_file = self.input_file_path.text()
            if not input_file:
                QMessageBox.warning(self, "Error", "Please select an input file.")
                return
            try:
                with open(input_file, "rb") as f:
                    data_raw = f.read()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to read input file: {e}")
                return
        else:
            input_text = self.input_text.toPlainText()
            if not input_text:
                QMessageBox.warning(self, "Error", "Please enter text to decrypt.")
                return
            try:
                data_raw = base64.b64decode(input_text.encode("utf-8"))
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Invalid base64 input: {e}")
                return

        # extract params from encrypted data
        try:
            kdf = KDF.from_bytes(data_raw)
            data = data_raw[kdf.params.BINARY_SIZE :]  # remove params from data
        except ValueError:
            if self.kdf.currentText() == "Scrypt":
                n = self.scrypt_n_input.value() * 1024  # convert to KB
                r = self.scrypt_r_input.value()
                p = self.scrypt_p_input.value()
                params = ScryptParams(n, r, p)
            elif self.kdf.currentText() == "Argon2":
                time_cost = self.argon2_time_input.value()
                memory_cost = self.argon2_memory_input.value() * 1024  # convert to KB
                parallelism = self.argon2_parallelism_input.value()
                params = Argon2Params(time_cost, memory_cost, parallelism)
            elif self.kdf.currentText() == "PBKDF2":
                iterations = self.pbkdf2_iter_input.value()
                params = Pbkdf2Params(iterations)
            kdf = KDF(params, 32)
            data = data_raw
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to extract KDF params: {e}")
            return

        key = key_text.encode("utf-8")
        cipher = Cipher(key, kdf=kdf)

        # Decrypt data
        try:
            if self.algorithm.currentText() == "AES-GCM":
                decrypted_data = cipher.decrypt_aesgcm(data)
            else:
                decrypted_data = cipher.decrypt_legacy(data)
        except ValueError as e:
            QMessageBox.warning(self, "Error", f"{e}")
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
    # app.setWindowIcon(QIcon("cipher/assets/icon.png"))
    window = CipherApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
