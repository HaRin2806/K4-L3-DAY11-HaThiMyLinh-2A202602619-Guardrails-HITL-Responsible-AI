"""
Script khởi chạy giao diện Demo tương tác: VinBank AI Security & Guardrails Studio
Tự động mở trình duyệt web tại http://localhost:8000/demo/
"""
import http.server
import socketserver
import webbrowser
import os
import sys

PORT = 8000
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

def start_demo():
    print(f"\n=======================================================")
    print(f"🚀 Đang khởi động VinBank AI Guardrails Demo Studio...")
    print(f"🔗 URL: http://localhost:{PORT}/demo/index.html")
    print(f"💡 Nhấn Ctrl + C để dừng máy chủ bất cứ lúc nào.")
    print(f"=======================================================\n")
    
    # Mở trình duyệt tự động
    webbrowser.open(f"http://localhost:{PORT}/demo/index.html")
    
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 Đã dừng máy chủ demo.")

if __name__ == "__main__":
    start_demo()
