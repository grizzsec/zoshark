import sys
import threading
from scapy.all import *
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QWidget, QPushButton, QLabel, QFileDialog, QComboBox, QLineEdit,
    QGroupBox, QFormLayout, QTreeWidget, QTreeWidgetItem, QTextBrowser, QSplitter, QSlider, QTableWidget,
    QTableWidgetItem, QHeaderView, QMessageBox, QAction, QMenuBar, QToolBar, QMenu, QActionGroup, QCheckBox,
    QStackedWidget
)
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt

class ZoShark(QMainWindow):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setGeometry(100, 100, 1200, 800)
        self.setWindowTitle('ZoShark - Captura de Paquetes')
        self.setWindowIcon(QIcon('zoshark.png'))

        # Crear una barra de menú
        menubar = self.menuBar()

        # Menú Archivo
        file_menu = menubar.addMenu('Archivo')

        save_action = QAction('Guardar Paquetes', self)
        save_action.triggered.connect(self.save_packets)
        file_menu.addAction(save_action)

        exit_action = QAction('Salir', self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Menú Ayuda
        help_menu = menubar.addMenu('Ayuda')

        about_action = QAction('Acerca de', self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)

        # Menú Ver
        view_menu = menubar.addMenu('Ver')

        packet_view_action = QAction('Vista de Paquetes', self)
        packet_view_action.setCheckable(True)
        packet_view_action.setChecked(True)
        packet_view_action.triggered.connect(self.toggle_packet_view)
        view_menu.addAction(packet_view_action)

        table_view_action = QAction('Vista de Tabla', self)
        table_view_action.setCheckable(True)
        table_view_action.setChecked(False)
        table_view_action.triggered.connect(self.toggle_table_view)
        view_menu.addAction(table_view_action)

        view_group = QActionGroup(self)
        view_group.addAction(packet_view_action)
        view_group.addAction(table_view_action)

        # Barra de herramientas
        toolbar = QToolBar()
        self.addToolBar(toolbar)

        # Configuración de filtrado avanzado
        self.advanced_filter_group = QGroupBox('Filtrado Avanzado')
        advanced_filter_layout = QFormLayout()

        self.custom_filter_label = QLabel('Filtro Personalizado (Sintaxis BPF):')
        self.custom_filter_input = QLineEdit()
        self.custom_filter_input.setPlaceholderText('Deja vacío para sin filtro')

        advanced_filter_layout.addRow(self.custom_filter_label, self.custom_filter_input)

        self.protocol_filter_label = QLabel('Filtrar por Protocolo:')
        self.protocol_filter_combo = QComboBox()
        self.protocol_filter_combo.addItem('Todos los protocolos')
        self.protocol_filter_combo.addItem('HTTP')
        self.protocol_filter_combo.addItem('SSH')
        self.protocol_filter_combo.addItem('DNS')
        self.protocol_filter_combo.addItem('Otros')
        self.protocol_filter_combo.currentIndexChanged.connect(self.update_protocol_filter)

        advanced_filter_layout.addRow(self.protocol_filter_label, self.protocol_filter_combo)

        self.advanced_filter_group.setLayout(advanced_filter_layout)
        toolbar.addWidget(self.advanced_filter_group)

        # Opciones avanzadas
        self.advanced_options_group = QGroupBox('Opciones Avanzadas')
        advanced_options_layout = QFormLayout()

        self.promiscuous_mode_checkbox = QCheckBox('Modo Promiscuo (Captura Todos)')
        advanced_options_layout.addRow(self.promiscuous_mode_checkbox)

        self.advanced_options_group.setLayout(advanced_options_layout)
        toolbar.addWidget(self.advanced_options_group)

        # Captura de Paquetes en Red
        self.capture_group = QGroupBox('Captura de Paquetes en Red')
        capture_layout = QFormLayout()

        self.start_capture_button = QPushButton('Iniciar Captura')
        self.stop_capture_button = QPushButton('Detener Captura')

        capture_layout.addRow(self.start_capture_button, self.stop_capture_button)

        self.capture_group.setLayout(capture_layout)
        toolbar.addWidget(self.capture_group)

        # Visualización de Paquetes en Árbol
        self.packet_tree = QTreeWidget()
        self.packet_tree.setHeaderLabels(['Campo', 'Valor'])
        self.packet_tree.setColumnWidth(0, 200)
        self.packet_tree.setColumnWidth(1, 600)

        self.layout = QVBoxLayout()
        self.layout.addWidget(self.packet_tree)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.central_widget.setLayout(self.layout)

        self.start_capture_button.clicked.connect(self.start_packet_capture)
        self.stop_capture_button.clicked.connect(self.stop_packet_capture)

        self.sniffing = False
        self.packet_thread = None
        self.interface = None
        self.packets = []

        self.build_packet_tree()

    def build_packet_tree(self):
        # Esto es un ejemplo de cómo puedes mostrar detalles de paquetes en el árbol.
        # Debes personalizar esto según tus necesidades.

        # Crear un paquete de ejemplo (reemplaza esto con tus propios paquetes capturados)
        example_packet = Ether(dst="00:00:00:00:00:01") / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=80, dport=1234)

        # Limpiar el árbol
        self.packet_tree.clear()

        # Crear un elemento raíz
        root_item = QTreeWidgetItem(self.packet_tree)
        root_item.setText(0, 'Paquete de Ejemplo')
        root_item.setText(1, '')

        # Agregar campos y valores del paquete de ejemplo al árbol
        self.add_packet_fields_to_tree(example_packet, root_item)

        # Expandir el elemento raíz
        root_item.setExpanded(True)

    def add_packet_fields_to_tree(self, packet, parent_item):
        # Esta función agrega campos y valores de paquetes al árbol.
        # Puedes personalizar esto para mostrar detalles específicos de tus paquetes capturados.
        for field, value in packet.fields.items():
            if isinstance(value, Packet):
                # Si el campo contiene otro paquete, crear un nuevo elemento para él
                item = QTreeWidgetItem(parent_item)
                item.setText(0, field)
                item.setText(1, '')
                self.add_packet_fields_to_tree(value, item)
            else:
                # Mostrar el campo y su valor
                item = QTreeWidgetItem(parent_item)
                item.setText(0, field)
                item.setText(1, str(value))

    def start_packet_capture(self):
        # Aquí puedes iniciar la captura de paquetes en la red utilizando Scapy.
        # Añade tu lógica de captura aquí.
        pass

    def stop_packet_capture(self):
        # Aquí puedes detener la captura de paquetes en la red si es necesario.
        # Añade tu lógica de detención aquí.
        pass

    def save_packets(self):
        if not self.packets:
            return

        filename, _ = QFileDialog.getSaveFileName(self, 'Guardar Paquetes', '', 'Archivos PCAP (*.pcap)')
        if filename:
            wrpcap(filename, self.packets)

    def show_about_dialog(self):
        QMessageBox.about(self, 'Acerca de ZoShark', 'ZoShark es una herramienta de captura de paquetes en red. Licencia de uso no comercial.')

    def toggle_packet_view(self):
        # Función para cambiar a la vista de paquetes (personaliza según tus necesidades)
        pass

    def toggle_table_view(self):
        # Función para cambiar a la vista de tabla (personaliza según tus necesidades)
        pass

    def update_protocol_filter(self):
        # Función para actualizar el filtro de protocolo (personaliza según tus necesidades)
        pass

    def update_packet_view(self):
        # Función para actualizar la vista de paquetes (personaliza según tus necesidades)
        pass

    def update_table_view(self):
        # Función para actualizar la vista de tabla (personaliza según tus necesidades)
        pass

def main():
    app = QApplication(sys.argv)
    ex = ZoShark()
    ex.show()

    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
