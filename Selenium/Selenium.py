from selenium import webdriver
from selenium.webdriver.common.by import By
import time

# إدخال اسم الكورس
course_name = input("أدخل اسم الكورس: ")

# إعداد WebDriver
driver = webdriver.Chrome()  # تأكد من أن لديك ChromeDriver في مسار النظام

# فتح موقع يوتيوب
driver.get('https://www.youtube.com')

# انتظر حتى يتم تحميل الصفحة
time.sleep(3)

# البحث عن فيديو (استبدل 'اسم الفيديو' بالنص الذي تريد البحث عنه)
search_box = driver.find_element(By.NAME, 'search_query')
search_box.send_keys(course_name)
search_box.submit()

# انتظر حتى يتم تحميل نتائج البحث
time.sleep(3)

# الحصول على جميع الفيديوهات من نتائج البحث
videos = driver.find_elements(By.ID, 'video-title')

# عرض عناوين الفيديوهات وروابطها
for video in videos:
    title = video.get_attribute('title')
    link = video.get_attribute('href')
    print(f'Title: {title}, Link: {link}')

# إغلاق المتصفح
driver.quit()