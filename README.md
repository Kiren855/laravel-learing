# BugBuster
Dự án phát triển phần mềm quản lý lỗi sử dụng framework Laravel.
### Thành viên nhóm
- **[Giảng viên hướng dẫn: Nguyễn Lệ Thu](https://github.com/nglthu)**
- **[Bùi Văn Công](https://github.com/CNG03)**
- **[Trần Ngọc Lâm](https://github.com/tranngoclamm)**
- **[Nông Ngọc Huân](https://github.com/Kiren855)**
## Cài đặt dự án.
- Cài đặt Laragon hoặc Xampp để chạy serve.
- Cài đặt Composer(v2.7.1) để chạy được composer phải thực hiện cài đặt Php và thực hiện cấu hình php vào trong biến môi trường ở trong máy tính.
## Tạo dự án.
- Thực hiện tạo dự án với composer `composer create-project laravel/laravel BugBuster`.
- Dự án sẽ được tạo thành công.
- Di chuyển thư mục dự án vừa tạo vào trong thư mục có đường dẫn sau: `laragon\www`.
- Mở dự án với Visual Studio Code, mở terminal và gõ `php artisan serve`.
- Trong terminal sẽ xuất hiện một đường link click vào đó để mở dự án, mặc định dự án sẽ chạy vào file `resources/views/welcome.blade.php`
- Thực hiện chỉnh sửa file này để in ra màn hình chữ Hello, world!.
```
<?php 
    echo '<h1>Hello, World!</h1>';
?>
```
- Tải lại trang để xem sự thay đổi.
## Chạy dự án cho thành viên trong team.
- Cài Composer và Php.
- Cài laragon hoặc Xampp.
- Clone dự án từ Github.
- Mở terminal trong Visual Studio Code, gõ `composer install`.
- Tiếp tục chạy lệnh sau `cp .env.example .env`.
- Thực hiện tạo khóa cho ứng dụng `php artisan key:generate`
- Cuối cùng là chạy ứng dụng với `php artisan serve`.