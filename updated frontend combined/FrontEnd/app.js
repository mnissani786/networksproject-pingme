document.getElementById('registerForm').addEventListener('submit', function(event) {
    event.preventDefault();

    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    if (password !== confirmPassword) {
        alert('Passwords do not match!');
        return;
    }

    // ✅ OPTION 1: Using LocalStorage (simpler, but less secure)
    localStorage.setItem('user', JSON.stringify({ username, email, password }));
    alert('Registration successful!');

    // ✅ OPTION 2: Using Firebase Authentication (comment out LocalStorage part above if using this)
    /*
    firebase.auth().createUserWithEmailAndPassword(email, password)
        .then(() => alert('Registration successful!'))
        .catch(error => alert(error.message));
    */
});
