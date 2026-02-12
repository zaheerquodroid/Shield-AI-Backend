"""
Test file for CSEC-33: Missing PostgreSQL RLS
This file contains models with tenant_id that should trigger RLS detection.
"""

from django.db import models


# Test Case 1: Model with tenant_id field (should detect)
class Document(models.Model):
    """Document model with tenant_id - needs RLS"""
    tenant_id = models.IntegerField()
    title = models.CharField(max_length=200)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'app_document'


# Test Case 2: Model with tenant ForeignKey (should detect)
class Comment(models.Model):
    """Comment model with tenant FK - needs RLS"""
    tenant = models.ForeignKey('Tenant', on_delete=models.CASCADE)
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'app_comment'


# Test Case 3: Model with organization FK (should detect)
class Project(models.Model):
    """Project model with organization FK - needs RLS"""
    organization = models.ForeignKey('Organization', on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    description = models.TextField()

    class Meta:
        db_table = 'app_project'


# Test Case 4: Global model without tenant (should NOT detect)
class Country(models.Model):
    """Country model - no tenant, no RLS needed"""
    name = models.CharField(max_length=100)
    code = models.CharField(max_length=2)


class Tenant(models.Model):
    """Tenant model itself - no RLS needed"""
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)


class Organization(models.Model):
    """Organization model - tenant parent"""
    name = models.CharField(max_length=100)
