<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        /* body{
    
} */

form{
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
}

h1 {
    text-align: center;
}
    </style>
    <title>Sign Up</title>
</head>
<body>
    <div class="form_container">
        <h1>Sign up</h1>
        <form action="<?php echo(htmlspecialchars($_SERVER["PHP_SELF"]))?>" method="POST">
           <label for="fname">Enter your first name</label>
           <input type="text" name="fname" id="fname" required aria-required="true">
           <label for="mname">Enter your middle name <i>Optional</i></label>
           <input type="text" name="mname" id="mname" placeholder="Optional">
           <label for="surname">Enter your surname</label>
           <input type="text" name="surname" id="surname" required aria-required="true">
           <label for="country">Enter your country</label>
           <input type="text" name="country" id="country" required aria-required="true">
           <label for="tel">Phone Number</label>
           <input type="tel" name="tel" id="tel" required aria-required="true">
           <label for="email">Enter your email address</label>
           <input type="email" id="email" name="email" required aria-required="true">
           <label for="password">Enter a password</label>
           <input type="password" id="password" name="password" required aria-required="true">
           <label for="confirm-password">Confirm your password</label>
           <input type="password" id="confirm-password" name="confirm-password">
           <input type="submit" value="sign up">
        </form>
    </div>
    <div class="footer">
        <footer>
            <p>&COPY;;</p>
        </footer>
    </div>
</body>
</html>

<?php
// Configuration
$dbHost = 'localhost';
$dbUsername = 'root';
$dbPassword = '';
$dbName = 'test';

// Connect to database
try {
    $conn = new PDO("mysql:host=$dbHost;dbname=$dbName", $dbUsername, $dbPassword);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    echo "Connection failed: " . $e->getMessage();
}

// Function to clean and validate input data
function cleanData($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}

// Function to validate password
function validatePassword($password, $confirmPassword) {
    $errors = array();
    if (empty($password) || empty($confirmPassword)) {
        $errors[] = new Exception("Passwords are required!");
    } else {
        // Sanitize passwords
        $password = cleanData($password);
        $confirmPassword = cleanData($confirmPassword);

        // Check password length
        if (strlen($password) < 8) {
            $errors[] = new Exception("Password must be at least 8 characters long!");
        }

        // Check password strength
        if (!preg_match("/[A-Z]/", $password)) {
            $errors[] = new Exception("Password must contain at least one uppercase letter!");
        }
        if (!preg_match("/[a-z]/", $password)) {
            $errors[] = new Exception("Password must contain at least one lowercase letter!");
        }
        if (!preg_match("/[0-9]/", $password)) {
            $errors[] = new Exception("Password must contain at least one digit!");
        }
        $Special_Char_Pattern = "/[!@#$%^&*()_-{}:;',.?]/";
        if (!preg_match($Special_Char_Pattern, $password)) {
            $errors[] = new Exception("Password must contain at least one special character!");
        }

        // Check if confirmed password matches password
        if ($password != $confirmPassword) {
            $errors[] = new Exception("Passwords do not match!");
        }
    }
    return $errors;
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Clean and validate input data
    $fname = cleanData($_POST['fname']);
    $mname = cleanData($_POST['mname']);
    $surname = cleanData($_POST['surname']);
    $country = cleanData($_POST['country']);
    $tel = cleanData($_POST['tel']);
    $email = cleanData($_POST['email']);
    $password = cleanData($_POST['password']);
    $confirmPassword = cleanData($_POST['confirm-password']);

    // Validate input data
    $errors = array();
    if (empty($fname)) {
        $errors[] = new Exception("First name is required!");
    }
    if (!preg_match("/^[a-zA-Z]+$/", $fname)) {
        $errors[] = new Exception("Invalid first name!");
    }
    if (empty($surname)) {
        $errors[] = new Exception("Surname is required!");
    }
    if (!preg_match("/^[a-zA-Z]+$/", $surname)) {
        $errors[] = new Exception("Invalid surname!");
    }
    if (empty($country)) {
        $errors[] = new Exception("Country is required!");
    }
    if (!preg_match("/^[a-zA-Z]+$/", $country)) {
        $errors[] = new Exception("Invalid country!");
    }
    if (empty($tel)) {
        $errors[] = new Exception("Phone number is required!");
    }
    if (!preg_match("/^[0-9]+$/", $tel) || strlen($tel) != 10) {
        $errors[] = new Exception("Invalid phone number!");
    }
    if (empty($email)) {
        $errors[] = new Exception("Email is required!");
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = new Exception("Invalid email format!");
    }

    // Validate password
    $passwordErrors = validatePassword($password, $confirmPassword);
    if (!empty($passwordErrors)) {
        $errors = array_merge($errors, $passwordErrors);
    }

    // Check if there are any errors
    if (!empty($errors)) {
        foreach ($errors as $error) {
            echo $error->getMessage() . "<br>";
        }
    } else {
        // Hash password
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);

        // Prepare and bind SQL statement
        $query = "INSERT INTO subscribers(FirstName, MiddleName, Surname, Country, PhoneNumber, Email, Password) VALUES(:firstname, :middlename, :surname, :country, :phoneNumber, :email, :password)";
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':firstname', $fname);
        $stmt->bindParam(':middlename', $mname);
        $stmt->bindParam(':surname', $surname);
        $stmt->bindParam(':country', $country);
        $stmt->bindParam(':phoneNumber', $tel);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':password', $passwordHash);

        // Insert data into database
        if ($stmt->execute()) {
            echo "New record created successfully";
        } else {
            echo "Error: " . $stmt->errorInfo()[2];
        }
    }
}

// Close database connection
$conn = null;
?>

