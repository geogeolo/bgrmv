import sqlite3
import bcrypt
import streamlit as st
import pandas as pd
from rembg import remove
from PIL import Image
import io
import re
import logging

# 設定日誌記錄
logging.basicConfig(level=logging.INFO)

# 資料庫操作模組
def initialize_db():
    with sqlite3.connect('backusers.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT,
            credits INTEGER DEFAULT 10,
            security_question TEXT,
            security_answer TEXT
        )
        ''')
        # 添加缺少的欄位
        cursor.execute('PRAGMA table_info(users)')
        columns = [col[1] for col in cursor.fetchall()]
        if 'security_question' not in columns:
            cursor.execute('ALTER TABLE users ADD COLUMN security_question TEXT')
        if 'security_answer' not in columns:
            cursor.execute('ALTER TABLE users ADD COLUMN security_answer TEXT')

        # 插入一個範例用戶（用戶名: admin, 密碼: admin）
        username = 'admin'
        password = 'admin'
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        security_question = 'Your favorite color?'
        security_answer = bcrypt.hashpw('blue'.encode('utf-8'), bcrypt.gensalt())
        cursor.execute('''
        INSERT OR REPLACE INTO users (username, password, credits, security_question, security_answer) VALUES (?, ?, ?, ?, ?)
        ''', (username, hashed.decode('utf-8'), 10, security_question, security_answer.decode('utf-8')))
        conn.commit()
    logging.info("Database initialized.")

def check_credentials(username, password):
    with sqlite3.connect('backusers.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT password, credits FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
    if result:
        stored_password, credits = result
        if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
            return True, credits
    return False, 0

def update_credits(username, amount):
    with sqlite3.connect('backusers.db') as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET credits = credits + ? WHERE username = ?', (amount, username))
        conn.commit()
    logging.info(f"Updated credits for user {username}: {amount}")

# 圖片處理模組
def remove_background(image):
    img_byte_arr = io.BytesIO()
    image.save(img_byte_arr, format='PNG')
    img_byte_arr = img_byte_arr.getvalue()
    output = remove(img_byte_arr)
    return Image.open(io.BytesIO(output))

# 驗證信用卡號
def validate_card_number(card_number):
    return re.fullmatch(r'^[0-9]{16}$', card_number) is not None

# 驗證到期日
def validate_expiry_date(expiry_date):
    return re.fullmatch(r'^(0[1-9]|1[0-2])\/[0-9]{2}$', expiry_date) is not None

# 驗證CVV
def validate_cvv(cvv):
    return re.fullmatch(r'^[0-9]{3}$', cvv) is not None

# 初始化 session state
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
    st.session_state['username'] = ''
    st.session_state['credits'] = 0
    st.session_state['original_image'] = None
    st.session_state['processed_image'] = None

# 頁面
def login_page():
    st.subheader('登入')
    username = st.text_input('用戶名')
    password = st.text_input('密碼', type='password')
    if st.button('登入'):
        valid, credits = check_credentials(username, password)
        if valid:
            st.session_state['logged_in'] = True
            st.session_state['username'] = username
            st.session_state['credits'] = credits
            st.experimental_rerun()
        else:
            st.error('用戶名或密碼錯誤')

def register_page():
    st.subheader('註冊')
    new_username = st.text_input('用戶名')
    new_password = st.text_input('密碼', type='password')
    confirm_password = st.text_input('確認密碼', type='password')
    security_question = st.text_input('安全問題')
    security_answer = st.text_input('安全問題答案')
    
    if st.button('註冊'):
        if new_password != confirm_password:
            st.error('密碼不匹配')
        else:
            hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            hashed_answer = bcrypt.hashpw(security_answer.encode('utf-8'), bcrypt.gensalt())
            with sqlite3.connect('backusers.db') as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute('''
                    INSERT INTO users (username, password, credits, security_question, security_answer) VALUES (?, ?, ?, ?, ?)
                    ''', (new_username, hashed.decode('utf-8'), 10, security_question, hashed_answer.decode('utf-8')))
                    conn.commit()
                    st.success('註冊成功！')
                except sqlite3.IntegrityError:
                    st.error('用戶名已存在')

def main_page():
    st.subheader('歡迎！')
    st.write(f'您還有 {st.session_state["credits"]} 點數。')

    uploaded_file = st.file_uploader('上傳圖片', type=['jpg', 'png', 'jpeg'])
    if uploaded_file:
        image = Image.open(uploaded_file)
        st.session_state['original_image'] = image
        st.session_state['processed_image'] = None

    if st.session_state['original_image']:
        st.image(st.session_state['original_image'], caption='原始圖片', use_column_width=True)

        if st.button('移除背景') and st.session_state['credits'] > 0:
            try:
                result = remove_background(st.session_state['original_image'])
                st.session_state['processed_image'] = result
                update_credits(st.session_state['username'], -1)
                st.session_state['credits'] -= 1
            except Exception as e:
                st.error(f"處理圖片時出現錯誤: {e}")
                logging.error(f"Error processing image: {e}")
        elif st.session_state['credits'] == 0:
            st.warning('您的點數已用完，請充值。')

    if st.session_state['processed_image']:
        st.image(st.session_state['processed_image'], caption='移除背景後的圖片', use_column_width=True)

def top_up_page():
    st.subheader('充值點數')
    st.write('模擬信用卡充值：')
    
    card_number = st.text_input('信用卡號')
    expiry_date = st.text_input('到期日（MM/YY）')
    cvv = st.text_input('CVV', type='password')
    amount = st.number_input('輸入充值金額', min_value=1, max_value=100)
    
    if st.button('充值'):
        if not validate_card_number(card_number):
            st.error('無效的信用卡號')
        elif not validate_expiry_date(expiry_date):
            st.error('無效的到期日，格式應為MM/YY')
        elif not validate_cvv(cvv):
            st.error('無效的CVV，應為三位數字')
        else:
            update_credits(st.session_state['username'], amount)
            st.session_state['credits'] += amount
            st.success(f'成功增加 {amount} 點數！')
            st.experimental_rerun()

def is_admin(username):
    return username == 'admin'

def admin_page():
    st.subheader('管理員頁面')
    with sqlite3.connect('backusers.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT username, credits FROM users')
        users = cursor.fetchall()
        df = pd.DataFrame(users, columns=['Username', 'Credits'])
        st.dataframe(df)
        
        selected_user = st.selectbox('選擇用戶', df['Username'])
        new_credits = st.number_input('設置新的點數', min_value=0)
        if st.button('更新點數'):
            cursor.execute('UPDATE users SET credits = ? WHERE username = ?', (new_credits, selected_user))
            conn.commit()
            st.success('點數更新成功')

def forgot_password_page():
    st.subheader('重置密碼')
    username = st.text_input('用戶名')
    
    if st.button('下一步'):
        with sqlite3.connect('backusers.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT security_question FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
        
        if result:
            security_question = result[0]
            st.session_state['username_for_reset'] = username
            st.session_state['security_question'] = security_question
            st.experimental_rerun()
        else:
            st.error('用戶名不存在')

def answer_security_question_page():
    st.subheader('重置密碼')
    st.write(f"安全問題: {st.session_state['security_question']}")
    security_answer = st.text_input('安全問題答案')
    
    if st.button('驗證答案'):
        with sqlite3.connect('backusers.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT security_answer FROM users WHERE username = ?', (st.session_state['username_for_reset'],))
            result = cursor.fetchone()
        
        if result and bcrypt.checkpw(security_answer.encode('utf-8'), result[0].encode('utf-8')):
            st.session_state['verified'] = True
            st.experimental_rerun()
        else:
            st.error('答案不正確')

def reset_password_page():
    st.subheader('重置密碼')
    new_password = st.text_input('新密碼', type='password')
    confirm_password = st.text_input('確認新密碼', type='password')
    
    if st.button('重置密碼'):
        if new_password != confirm_password:
            st.error('密碼不匹配')
        else:
            hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            with sqlite3.connect('backusers.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                UPDATE users SET password = ? WHERE username = ?
                ''', (hashed.decode('utf-8'), st.session_state['username_for_reset']))
                conn.commit()
                st.success('密碼重置成功！')
                st.session_state['verified'] = False
                st.session_state['username_for_reset'] = None
                st.session_state['security_question'] = None
                st.experimental_rerun()

# 主應用程式邏輯
if st.session_state['logged_in']:
    st.sidebar.title('導航')
    if is_admin(st.session_state['username']):
        page = st.sidebar.radio('前往', ['主頁面', '充值點數', '管理員頁面', '登出'])
    else:
        page = st.sidebar.radio('前往', ['主頁面', '充值點數', '登出'])

    if page == '主頁面':
        main_page()
    elif page == '充值點數':
        top_up_page()
    elif page == '管理員頁面':
        admin_page()
    elif page == '登出':
        st.session_state['logged_in'] = False
        st.session_state['username'] = ''
        st.session_state['credits'] = 0
        st.session_state['original_image'] = None
        st.session_state['processed_image'] = None
        st.success('已成功登出！')
        st.experimental_rerun()
else:
    auth_page = st.sidebar.radio('前往', ['登入', '註冊', '忘記密碼'])
    if auth_page == '登入':
        login_page()
    elif auth_page == '註冊':
        register_page()
    elif auth_page == '忘記密碼':
        if 'verified' in st.session_state and st.session_state['verified']:
            reset_password_page()
        elif 'username_for_reset' in st.session_state and st.session_state['username_for_reset']:
            answer_security_question_page()
        else:
            forgot_password_page()

# 初始化資料庫
initialize_db()
