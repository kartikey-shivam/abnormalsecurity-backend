# abnormalsecurity-backend
# Secure File Share System

A secure file sharing system built with Django REST Framework that supports Multi-Factor Authentication, file encryption, and granular access control.

## Technologies Used

### Backend
- Python 3.5+
- Django 3.2+
- Django REST Framework
- PostgreSQL
- django-otp (Multi-Factor Authentication)
- cryptography (File Encryption)

### Security Features
- JWT Authentication
- Email-based MFA
- File Encryption
- Role-based Access Control
- Secure File Storage

## Features

1. **User Authentication**
   - JWT-based authentication
   - Multi-Factor Authentication (MFA)
   - Role-based access (Admin, Regular User, Guest)

2. **File Management**
   - Secure file upload with encryption
   - File download with decryption
   - View files in browser
   - File sharing with other users

3. **Access Control**
   - Role-based permissions
   - File sharing permissions (view/download)
   - Time-limited file access

4. **Security**
   - Encrypted file storage
   - MFA protection
   - Secure file transmission
   - Access logging




## Security Considerations

1. **File Security**
   - All files are encrypted at rest
   - Secure transmission using HTTPS
   - Access control checks on every request

2. **Authentication**
   - JWT token expiration
   - MFA for sensitive operations
   - Role-based access control

3. **Data Protection**
   - PostgreSQL database encryption
   - Secure file storage
   - Protected media access

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
## License

MIT License - see LICENSE file

## Authors

- Frontend: [abnormalsecurity-frontend]([https://github.com/kartikey-shivam/abnormalsecurity-frontend](https://github.com/kartikey-shivam/abnormalsecurity-frontend))

# abnormalsecurity-backend
