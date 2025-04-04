document.getElementById('recoveryForm').addEventListener('submit', function(event) {
    event.preventDefault();

    const email = document.getElementById('email').value;

    // ✅ OPTION 1: Check if email exists in LocalStorage (not secure but works without a backend)
    const user = JSON.parse(localStorage.getItem('user'));
    if (user && user.email === email) {
        alert('Password reset link would be sent to your email (mock).');
    } else {
        alert('Email not found!');
    }

    // ✅ OPTION 2: Firebase Authentication (comment out LocalStorage part above if using this)
    /*
    firebase.auth().sendPasswordResetEmail(email)
        .then(() => alert('Password reset email sent!'))
        .catch(error => alert(error.message));
    */
});
