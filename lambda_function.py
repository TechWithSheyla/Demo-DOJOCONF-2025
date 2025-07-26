import json
import boto3
import logging
import os
from botocore.exceptions import ClientError
from datetime import datetime

# Configurar logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Variables de entorno
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')

def lambda_handler(event, context):
    """
    Lambda para remediar el control S3.8 de Security Hub.
    Habilita Public Access Block en buckets S3.
    """
    
    logger.info(f"Evento recibido: {json.dumps(event)}")
    
    try:
        # Extraer información del evento original de Security Hub
        detail = event.get('detail', {})
        findings = detail.get('findings', [])
        
        if not findings:
            logger.error("No se encontraron findings en el evento")
            return {'statusCode': 400, 'body': 'No findings found'}
        
        finding = findings[0]
        
        # Extraer bucket del recurso
        resources = finding.get('Resources', [])
        if not resources:
            logger.error("No se encontraron recursos")
            return {'statusCode': 400, 'body': 'No resources found'}
        
        bucket_arn = resources[0].get('Id', '')
        if bucket_arn.startswith('arn:aws:s3:::'):
            bucket_name = bucket_arn.replace('arn:aws:s3:::', '')
        else:
            bucket_name = bucket_arn
        
        # Extraer otros datos
        finding_id = finding.get('Id')
        aws_account_id = finding.get('AwsAccountId')
        region = finding.get('Region')
        
        if not bucket_name:
            logger.error("Nombre del bucket no encontrado")
            return {'statusCode': 400, 'body': 'Bucket name missing'}
        
        logger.info(f"Remediando bucket: {bucket_name}")
        
        # Crear cliente S3
        s3_client = boto3.client('s3', region_name=region)
        
        # Habilitar Public Access Block
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        
        logger.info(f"Public Access Block habilitado para bucket: {bucket_name}")
        
        # Enviar notificación SNS
        send_sns_notification(bucket_name, region, context)
        
        # Actualizar hallazgo en Security Hub (opcional)
        if finding_id and aws_account_id:
            try:
                securityhub_client = boto3.client('securityhub', region_name=region)
                securityhub_client.batch_update_findings(
                    FindingIdentifiers=[{
                        'Id': finding_id,
                        'ProductArn': f'arn:aws:securityhub:{region}:{aws_account_id}:product/{aws_account_id}/default'
                    }],
                    Workflow={'Status': 'RESOLVED'},
                    Note={
                        'Text': 'Remediación automática: Public Access Block habilitado',
                        'UpdatedBy': 'Lambda-S3-Remediation'
                    }
                )
                logger.info(f"Hallazgo actualizado en Security Hub: {finding_id}")
            except Exception as e:
                logger.warning(f"No se pudo actualizar Security Hub: {str(e)}")
        
        return {
            'statusCode': 200,
            'body': json.dumps(f'Remediación exitosa para bucket: {bucket_name}')
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        logger.error(f"Error de AWS: {error_code} - {error_message}")
        
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error: {error_code} - {error_message}')
        }
        
    except Exception as e:
        logger.error(f"Error inesperado: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error inesperado: {str(e)}')
        }

def send_sns_notification(bucket_name, region, context):
    """Envía notificación SNS sobre la remediación"""
    if not SNS_TOPIC_ARN:
        logger.warning("SNS_TOPIC_ARN no configurado, saltando notificación")
        return
    
    try:
        sns_client = boto3.client('sns', region_name=region)
        
        message = {
            "bucket": bucket_name,
            "action": "Public Access Block habilitado",
            "control": "S3.8",
            "status": "Remediado exitosamente",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "requestId": context.aws_request_id
        }
        
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"S3 Remediación Completada - {bucket_name}",
            Message=json.dumps(message, indent=2)
        )
        
        logger.info(f"Notificación SNS enviada para bucket: {bucket_name}")
        
    except Exception as e:
        logger.warning(f"Error enviando notificación SNS: {str(e)}")