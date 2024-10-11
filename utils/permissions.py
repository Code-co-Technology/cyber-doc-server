from rest_framework.permissions import BasePermission


# Define role constants
ROLE_AUTHOR = 'author'
ROLE_STUDENT = 'student'
    

class IsAuthor(BasePermission):
    """Rights only for author"""
    def has_permission(self, request, view):
        return (request.user.is_authenticated and request.user.groups.filter(name='author').exists())
    

class IsStudent(BasePermission):
    """Rights only for student"""
    def has_permission(self, request, view):
        return (request.user.is_authenticated and request.user.groups.filter(name='student').exists() )
    

class IsLogin(BasePermission):
    """Rights only for Login"""
    def has_permission(self, request, view):
        return (request.user.is_authenticated)
