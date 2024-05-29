import sqlite3
import bcrypt
import streamlit as st
import pandas as pd
from rembg import remove
from PIL import Image, ImageEnhance
import io
import re
import smtplib
from email.mime.text import MIMEText
import logging
import matplotlib.pyplot as plt

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
            email TEXT,
            email_verified INTEGER DEFAULT 0,
            credits INTEGER DEFAULT 10,
            security_question TEXT,
            security_answer TEXT
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS image_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            original_image BLOB,
            processed_image BLOB,
            upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS credit_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            change INTEGER,
            reason TEXT,
            change_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            image_id INTEGER,
            feedback TEXT,
            feedback_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
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
            logging.info(f"User {username} logged in successfully.")
            return True, credits
    logging.warning(f"Failed login attempt for user {username}.")
    return False, 0

def update_credits(username, amount, reason):
    with sqlite3.connect('backusers.db') as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET credits = credits + ? WHERE username = ?', (amount, username))
        cursor.execute('''
        INSERT INTO credit_history (username, change, reason) VALUES (?, ?, ?)
        ''', (username, amount, reason))
        conn.commit()
    logging.info(f"Updated credits for user {username}: {amount} for reason: {reason}")

def save_image_history(username, original_image, processed_image):
    with sqlite3.connect('backusers.db') as conn:
        cursor = conn.cursor()
        orig_img_byte_arr = io.BytesIO()
        original_image.save(orig_img_byte_arr, format='PNG')
        proc_img_byte_arr = io.BytesIO()
        processed_image.save(proc_img_byte_arr, format='PNG')
        cursor.execute('''
        INSERT INTO image_history (username, original_image, processed_image) VALUES (?, ?, ?)
        ''', (username, orig_img_byte_arr.getvalue(), proc_img_byte_arr.getvalue()))
        conn.commit()

def remove_background(image):
    img_byte_arr = io.BytesIO()
    image.save(img_byte_arr, format='PNG')
    img_byte_arr = img_byte_arr.getvalue()
    output = remove(img_byte_arr)
    return Image.open(io.BytesIO(output))

def validate_card_number(card_number):
    return re.fullmatch(r'^[0-9]{16}$', card_number) is not None

def validate_expiry_date(expiry_date):
    return re.fullmatch(r'^(0[1-9]|1[0-2])\/[0-9]{2}$', expiry_date) is not None

def validate_cvv(cvv):
    return re.fullmatch(r'^[0-9]{3}$', cvv) is not None

def send_verification_email(email, verification_code):
    msg = MIMEText(f'您的驗證碼是: {verification_code}')
    msg['Subject'] = '郵件驗證'
    msg['From'] = 'your_email@example.com'
    msg['To'] = email

    with smtplib.SMTP('smtp.example.com', 587) as server:
        server.login('your_email@example.com', 'your_password')
        server.send_message(msg)

def notify_user(username, subject, message):
    with sqlite3.connect('backusers.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT email FROM users WHERE username = ?', (username,))
        email = cursor.fetchone()[0]
    send_verification_email(email, subject, message)

def edit_image(image, brightness=1.0, contrast=1.0):
    enhancer = ImageEnhance.Brightness(image)
    image = enhancer.enhance(brightness)
    enhancer = ImageEnhance.Contrast(image)
    image = enhancer.enhance(contrast)
    return image

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
    email = st.text_input('電子郵件')
    security_question = st.text_input('安全問題')
    security_answer = st.text_input('安全問題答案')
    
    if st.button('註冊'):
        if new_password != confirm_password:
            st.error('密碼不匹配')
        else:
            hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            hashed_answer = bcrypt.hashpw(security_answer.encode('utf-8'), bcrypt.gensalt())
            verification_code = '123456'  # 可以生成隨機碼
            send_verification_email(email, verification_code)
            with sqlite3.connect('backusers.db') as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute('''
                    INSERT INTO users (username, password, email, email_verified, credits, security_question, security_answer) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (new_username, hashed.decode('utf-8'), email, 0, 10, security_question, hashed_answer.decode('utf-8')))
                    conn.commit()
                    st.success('註冊成功！請檢查您的電子郵件以驗證您的帳號。')
                except sqlite3.IntegrityError:
                    st.error('用戶名或電子郵件已存在')

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
        
        brightness = st.slider('亮度', 0.1, 2.0, 1.0)
        contrast = st.slider('對比度', 0.1, 2.0, 1.0)
        
        edited_image = edit_image(st.session_state['original_image'], brightness, contrast)
        st.image(edited_image, caption='編輯後圖片', use_column_width=True)
        
        if st.button('移除背景') and st.session_state['credits'] > 0:
            try:
                result = remove_background(edited_image)
                st.session_state['processed_image'] = result
                update_credits(st.session_state['username'], -1, '圖片背景移除')
                st.session_state['credits'] -= 1
                save_image_history(st.session_state['username'], st.session_state['original_image'], result)
                
                feedback = st.text_area('請對本次圖片處理進行評價:', key='feedback')
                if st.button('提交評價'):
                    if feedback:
                        save_feedback(st.session_state['username'], result, feedback)
                        st.success('感謝您的評價！')
                    else:
                        st.warning('請填寫評價內容')
                        
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
            update_credits(st.session_state['username'], amount, '充值')
            st.session_state['credits'] += amount
            st.success(f'成功增加 {amount} 點數！')
            notify_user(st.session_state['username'], '點數充值成功', f'您已成功充值 {amount} 點數。')
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

def view_image_history():
    st.subheader('圖片歷史記錄')
    with sqlite3.connect('backusers.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, original_image, processed_image, upload_time FROM image_history WHERE username = ?', (st.session_state['username'],))
        images = cursor.fetchall()
    
    for img_id, orig_img, proc_img, upload_time in images:
        st.write(f"上傳時間: {upload_time}")
        original_image = Image.open(io.BytesIO(orig_img))
        processed_image = Image.open(io.BytesIO(proc_img))
        st.image(original_image, caption='原始圖片')
        st.image(processed_image, caption='處理後圖片')
        
        feedback = st.text_area(f'請對圖片 {img_id} 的處理結果進行評價:', key=f'feedback_{img_id}')
        if st.button('提交評價', key=f'submit_{img_id}'):
            if feedback:
                save_feedback(st.session_state['username'], img_id, feedback)
                st.success(f'感謝您對圖片 {img_id} 的評價！')
            else:
                st.warning('請填寫評價內容')
        
        if st.button('下載處理後圖片', key=f'download_{img_id}'):
            st.download_button('Download', data=proc_img, file_name=f'processed_{img_id}.png')

def view_credit_history():
    st.subheader('點數消耗記錄')
    with sqlite3.connect('backusers.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT change, reason, change_time FROM credit_history WHERE username = ?', (st.session_state['username'],))
        history = cursor.fetchall()
    
    for change, reason, change_time in history:
        st.write(f"{change_time}: {reason} - 點數變化: {change}")

def save_feedback(username, image_id, feedback):
    with sqlite3.connect('backusers.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO feedback (username, image_id, feedback) VALUES (?, ?, ?)
        ''', (username, image_id, feedback))
        conn.commit()

def view_feedback():
    st.subheader('用戶反饋')
    with sqlite3.connect('backusers.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT username, image_id, feedback, feedback_time FROM feedback')
        feedbacks = cursor.fetchall()
    
    for username, image_id, feedback, feedback_time in feedbacks:
        st.write(f"{feedback_time} - 用戶 {username} 對圖片 {image_id} 的反饋: {feedback}")

def admin_dashboard():
    st.subheader('管理員儀表板')
    with sqlite3.connect('backusers.db') as conn:
        cursor = conn.cursor()
        
        # 用戶活躍度
        cursor.execute('SELECT username, COUNT(*) FROM image_history GROUP BY username')
        user_activity = cursor.fetchall()
        st.write("用戶活躍度")
        user_activity_df = pd.DataFrame(user_activity, columns=['Username', 'ActivityCount'])
        st.dataframe(user_activity_df)
        
        # 繪製用戶活躍度曲線圖
        fig, ax = plt.subplots()
        ax.plot(user_activity_df['Username'], user_activity_df['ActivityCount'], marker='o')
        ax.set_xlabel('Username')
        ax.set_ylabel('Activity Count')
        ax.set_title('User Activity Count')
        st.pyplot(fig)
        
        # 點數使用情況
        cursor.execute('SELECT username, SUM(change) FROM credit_history GROUP BY username')
        credit_usage = cursor.fetchall()
        st.write("點數使用情況")
        credit_usage_df = pd.DataFrame(credit_usage, columns=['Username', 'TotalCreditsUsed'])
        st.dataframe(credit_usage_df)
        
        # 繪製點數使用情況曲線圖
        fig, ax = plt.subplots()
        ax.plot(credit_usage_df['Username'], credit_usage_df['TotalCreditsUsed'], marker='o', color='orange')
        ax.set_xlabel('Username')
        ax.set_ylabel('Total Credits Used')
        ax.set_title('User Credit Usage')
        st.pyplot(fig)

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

# 初始化 session state
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
    st.session_state['username'] = ''
    st.session_state['credits'] = 0
    st.session_state['original_image'] = None
    st.session_state['processed_image'] = None

# 主應用程式邏輯
if st.session_state['logged_in']:
    st.sidebar.title('導航')
    if is_admin(st.session_state['username']):
        page = st.sidebar.radio('前往', ['主頁面', '充值點數', '管理員頁面', '圖片歷史', '點數歷史', '用戶反饋', '管理員儀表板', '登出'])
    else:
        page = st.sidebar.radio('前往', ['主頁面', '充值點數', '圖片歷史', '點數歷史', '登出'])

    if page == '主頁面':
        main_page()
    elif page == '充值點數':
        top_up_page()
    elif page == '管理員頁面':
        admin_page()
    elif page == '圖片歷史':
        view_image_history()
    elif page == '點數歷史':
        view_credit_history()
    elif page == '用戶反饋':
        view_feedback()
    elif page == '管理員儀表板':
        admin_dashboard()
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
