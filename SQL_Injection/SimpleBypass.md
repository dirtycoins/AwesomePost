# SQL Injection: Phân tích và một số kỹ thuật bypass cơ bản

## 1. Giới thiệu

SQL Injection là một trong những lỗ hổng bảo mật web nguy hiểm và phổ biến nhất. Nó cho phép kẻ tấn công can thiệp vào các truy vấn mà ứng dụng gửi đến cơ sở dữ liệu. Trong bài viết này, chúng ta sẽ đi sâu vào cách SQL Injection hoạt động, các kỹ thuật bypass, và cách bảo vệ ứng dụng!

## 2. SQL Injection cơ bản

### 2.1 Cơ chế hoạt động

SQL Injection xảy ra khi dữ liệu đầu vào của người dùng được kết hợp trực tiếp vào câu lệnh SQL mà không được xử lý đúng cách.

Ví dụ, xét đoạn code PHP đơn giản sau:

```php
$username = $_POST['username'];
$password = $_POST['password'];

$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($connection, $query);
```

Nếu người dùng nhập username là `admin' --`, câu lệnh SQL sẽ trở thành:

```sql
SELECT * FROM users WHERE username='admin' --' AND password=''
```

Điều này cho phép đăng nhập vào tài khoản admin mà không cần mật khẩu.

## 3. Kỹ thuật bypass `cowban`

### 3.1 Mã hóa URL và thay đổi ký tự

#### Cơ chế:
Kỹ thuật này sử dụng mã hóa URL hoặc thay đổi ký tự để "ngụy trang" các từ khóa SQL.

#### Ví dụ:
```sql
%55nion(%53elect 1,2,3)
```

Giải mã:
- %55 = U
- %53 = S

Kết quả: `UNION(SELECT 1,2,3)`

### 3.2 Sử dụng khoảng trắng và ký tự đặc biệt

#### Cơ chế:
Kỹ thuật này sử dụng các ký tự đặc biệt và khoảng trắng để tách các từ khóa SQL.

#### Ví dụ:
```sql
+ UNION* DISTINCT* SELECT+
+ UNION* DISTINCTROW+SELECT+
```

### 3.3 Sử dụng ký tự xuống dòng (Line Feed)

#### Cơ chế:
Sử dụng ký tự xuống dòng để tách các từ khóa SQL.

#### Ví dụ:
```sql
%0AuNiOn
```

### 3.4 Thay đổi cách viết (Case Manipulation)

#### Cơ chế:
Thay đổi chữ hoa, chữ thường của các từ khóa SQL.

#### Ví dụ:
```sql
UnIoN SeLeCt
```

### 3.5 Kết hợp nhiều kỹ thuật

#### Ví dụ:
```sql
%55nion(%53elect 1,2,3)-- -
```

## 4. Tại sao các kỹ thuật này hoạt động?

1. **Xử lý không gian trắng linh hoạt**: DBMS thường cho phép nhiều loại khoảng trắng và ký tự đặc biệt trong câu lệnh SQL.
2. **Không phân biệt chữ hoa chữ thường**: Hầu hết các DBMS không phân biệt chữ hoa chữ thường trong từ khóa SQL.
3. **Hạn chế của bộ lọc**: Nhiều bộ lọc chỉ tìm kiếm các mẫu cụ thể và có thể bị vượt qua bằng các biến thể.
4. **Xử lý URL encoding**: Một số ứng dụng web tự động giải mã URL encoding trước khi xử lý đầu vào.
5. **Tính năng đặc biệt của DBMS**: Mỗi DBMS có thể có các tính năng riêng cho phép các cú pháp SQL đặc biệt.

## 5. Phòng chống nâng cao

### 5.1 Sử dụng Prepared Statements

```php
$stmt = $pdo->prepare('SELECT * FROM users WHERE username = :username AND password = :password');
$stmt->execute(['username' => $username, 'password' => $password]);
```

### 5.2 Implement WAF với quy tắc tùy chỉnh

```nginx
# Ví dụ với ModSecurity
SecRule ARGS "@rx (?i:(\%55|\%75|u)nion(\%20|\s|\+|/\*.*\*/)+(\%53|\%73|s)elect)" \
    "id:1000,phase:2,deny,status:403,msg:'Potential SQL Injection'"
```

### 5.3 Sử dụng Tokenization và Lexical Analysis

```python
import sqlparse

def is_safe_input(input_string):
    parsed = sqlparse.parse(input_string)
    for statement in parsed:
        if any(token.ttype is sqlparse.tokens.DML for token in statement.tokens):
            return False
    return True
```

### 5.4 Implement Context-Aware Escaping

```php
function escapeForLike($string) {
    return str_replace(['%', '_'], ['\%', '\_'], $string);
}

$safeName = escapeForLike($name);
$query = "SELECT * FROM users WHERE name LIKE '%$safeName%'";
```

### 5.5 Sử dụng Stored Procedures với tham số

```sql
CREATE PROCEDURE getUserByUsername
    @username NVARCHAR(50)
AS
BEGIN
    SELECT * FROM users WHERE username = @username
END
```

```csharp
using (SqlCommand cmd = new SqlCommand("getUserByUsername", connection))
{
    cmd.CommandType = CommandType.StoredProcedure;
    cmd.Parameters.Add("@username", SqlDbType.NVarChar).Value = username;
    // Execute the command
}
```

## 6. Kết luận

SQL Injection vẫn là một mối đe dọa nghiêm trọng, với các kỹ thuật tấn công ngày càng tinh vi. Việc hiểu rõ các phương pháp bypass tiên tiến giúp chúng ta xây dựng hệ thống phòng thủ mạnh mẽ hơn. Bằng cách kết hợp nhiều lớp bảo vệ, từ prepared statements đến WAF và phân tích cú pháp, chúng ta có thể giảm đáng kể nguy cơ bị tấn công SQL Injection.

Hãy nhớ rằng bảo mật là một quá trình liên tục. Luôn cập nhật kiến thức, theo dõi các xu hướng tấn công mới và điều chỉnh chiến lược bảo mật của bạn để đối phó với các mối đe dọa mới nổi.

---
## Tài liệu tham khảo
1. OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
2. MySQL Documentation: https://dev.mysql.com/doc/
3. PHP Manual: https://www.php.net/manual/en/security.database.sql-injection.php
4. SQL Injection Bypass Techniques: https://www.exploit-db.com/docs/english/41397-injecting-sqlite-database-based-applications.pdf
5. ModSecurity Reference Manual: https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)
