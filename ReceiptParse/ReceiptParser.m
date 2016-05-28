//
//  ReceiptParser.m
//  ReceiptParse
//
//  Created by weichao on 16/5/26.
//  Copyright © 2016年 FatGragon. All rights reserved.
//

#import "ReceiptParser.h"
#import <UIKit/UIkit.h>

#import <openssl/bio.h>
#import <openssl/pkcs7.h>
#import <openssl/evp.h>
#import <openssl/x509.h>

@implementation ReceiptParser

- (void)run {
    NSURL *receiptUrl = [self receiptUrl];
    PKCS7 *receiptPKCS7 = [self loadReceipData:receiptUrl];
    [self verifySignature:receiptPKCS7];
    [self parse:receiptPKCS7];
    
}

- (NSURL *)receiptUrl {
    NSURL *path = [[NSBundle mainBundle] URLForResource:@"sandboxReceipt" withExtension:@""];
    return path;
}

- (PKCS7 *)loadReceipData:(NSURL *)receiptURL {
    // Load the receipt file
    NSData *receiptData = [NSData dataWithContentsOfURL:receiptURL];
    
    // Create a memory buffer to extract the PKCS #7 container
    BIO *receiptBIO = BIO_new(BIO_s_mem());
    BIO_write(receiptBIO, [receiptData bytes], (int) [receiptData length]);
    PKCS7 *receiptPKCS7 = d2i_PKCS7_bio(receiptBIO, NULL);
    if (!receiptPKCS7) {
        // Validation fails
    }
    
    // Check that the container has a signature
    if (!PKCS7_type_is_signed(receiptPKCS7)) {
        // Validation fails
    }
    
    // Check that the signed container has actual data
    if (!PKCS7_type_is_data(receiptPKCS7->d.sign->contents)) {
        // Validation fails
    }
    return receiptPKCS7;
}


- (void)verifySignature:(PKCS7 *)receiptPKCS7 {
    // Load the Apple Root CA (downloaded from https://www.apple.com/certificateauthority/)
    NSURL *appleRootURL = [[NSBundle mainBundle] URLForResource:@"AppleIncRootCertificate" withExtension:@"cer"];
    NSData *appleRootData = [NSData dataWithContentsOfURL:appleRootURL];
    BIO *appleRootBIO = BIO_new(BIO_s_mem());
    BIO_write(appleRootBIO, (const void *) [appleRootData bytes], (int) [appleRootData length]);
    X509 *appleRootX509 = d2i_X509_bio(appleRootBIO, NULL);
    
    // Create a certificate store
    X509_STORE *store = X509_STORE_new();
    X509_STORE_add_cert(store, appleRootX509);
    
    // Be sure to load the digests before the verification
    OpenSSL_add_all_digests();
    
    // Check the signature
    int result = PKCS7_verify(receiptPKCS7, NULL, store, NULL, NULL, 0);
    if (result != 1) {
        // Validation fails
    }
}

- (void)parse:(PKCS7 *)receiptPKCS7 {
    // Get a pointer to the ASN.1 payload
    ASN1_OCTET_STRING *octets = receiptPKCS7->d.sign->contents->d.data;
    const unsigned char *ptr = octets->data;
    const unsigned char *end = ptr + octets->length;
    const unsigned char *str_ptr;
    const unsigned char *small_str_ptr;
    
    int type = 0, str_type = 0, small_str_type = 0;
    int xclass = 0, str_xclass = 0, small_str_xclass = 0;
    long length = 0, str_length = 0, small_str_length = 0;
    
    // Store for the receipt information
    NSString *bundleIdString = nil;
    NSString *bundleVersionString = nil;
    NSData *bundleIdData = nil;
    NSData *hashData = nil;
    NSData *opaqueData = nil;
    //weichao add
    NSDate *expirationDate = nil;
    NSDate *creationDate = nil;
    NSString *originalVersionString = nil;
    
    // Date formatter to handle RFC 3339 dates in GMT time zone
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    [formatter setDateFormat:@"yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'"];
    [formatter setTimeZone:[NSTimeZone timeZoneForSecondsFromGMT:0]];
    // Decode payload (a SET is expected)
    ASN1_get_object(&ptr, &length, &type, &xclass, end - ptr);
    if (type != V_ASN1_SET) {
        // Validation fails
    }
    while (ptr < end) {
        ASN1_INTEGER *integer;

        // Parse the attribute sequence (a SEQUENCE is expected)
        ASN1_get_object(&ptr, &length, &type, &xclass, end - ptr);
        if (type != V_ASN1_SEQUENCE) {
            // Validation fails
        }
        const unsigned char *seq_end = ptr + length;
        long attr_type = 0;
        long attr_version = 0;
        
        // Parse the attribute type (an INTEGER is expected)
        ASN1_get_object(&ptr, &length, &type, &xclass, end - ptr);
        if (type != V_ASN1_INTEGER) {
            // Validation fails
        }
        integer = c2i_ASN1_INTEGER(NULL, &ptr, length);
        attr_type = ASN1_INTEGER_get(integer);
        ASN1_INTEGER_free(integer);
        
        // Parse the attribute version (an INTEGER is expected)
        ASN1_get_object(&ptr, &length, &type, &xclass, end - ptr);
        if (type != V_ASN1_INTEGER) {
            // Validation fails
        }
        integer = c2i_ASN1_INTEGER(NULL, &ptr, length);
        attr_version = ASN1_INTEGER_get(integer);
        ASN1_INTEGER_free(integer);
        
        // Check the attribute value (an OCTET STRING is expected)
        ASN1_get_object(&ptr, &length, &type, &xclass, end - ptr);
        if (type != V_ASN1_OCTET_STRING) {
            // Validation fails
        }
        NSLog(@"enumerate Payload begin attr type:%li",attr_type);
        switch (attr_type) {
            case 2:
                // Bundle identifier
                str_ptr = ptr;
                ASN1_get_object(&str_ptr, &str_length, &str_type, &str_xclass, seq_end - str_ptr);
                if (str_type == V_ASN1_UTF8STRING) {
                    // We store both the decoded string and the raw data for later
                    // The raw is data will be used when computing the GUID hash
                    bundleIdString = [[NSString alloc] initWithBytes:str_ptr length:str_length encoding:NSUTF8StringEncoding];
                    bundleIdData = [[NSData alloc] initWithBytes:(const void *)ptr length:length];
                    NSLog(@"bundleIdString:%@",bundleIdString);
                }
                break;
                
            case 3:
                // Bundle version
                str_ptr = ptr;
                ASN1_get_object(&str_ptr, &str_length, &str_type, &str_xclass, seq_end - str_ptr);
                if (str_type == V_ASN1_UTF8STRING) {
                    // We store the decoded string for later
                    bundleVersionString = [[NSString alloc] initWithBytes:str_ptr length:str_length encoding:NSUTF8StringEncoding];
                    NSLog(@"bundleVersionString:%@",bundleVersionString);
                }
                break;
                
            case 4:
                // Opaque value
                opaqueData = [[NSData alloc] initWithBytes:(const void *)ptr length:length];
                break;
                
            case 5:
                // Computed GUID (SHA-1 Hash)
                hashData = [[NSData alloc] initWithBytes:(const void *)ptr length:length];
                break;
                
            case 21:
                // Expiration date
                str_ptr = ptr;
                ASN1_get_object(&str_ptr, &str_length, &str_type, &str_xclass, seq_end - str_ptr);
                if (str_type == V_ASN1_IA5STRING) {
                    // The date is stored as a string that needs to be parsed
                    NSString *dateString = [[NSString alloc] initWithBytes:str_ptr length:str_length encoding:NSASCIIStringEncoding];
                    expirationDate = [formatter dateFromString:dateString];
                    NSLog(@"expirationDate:%@",expirationDate);
                }
                break;
                
                // You can parse more attributes...
                // so i parse more attributes...
            case 12:
                // creationDate date
                str_ptr = ptr;
                ASN1_get_object(&str_ptr, &str_length, &str_type, &str_xclass, seq_end - str_ptr);
                if (str_type == V_ASN1_IA5STRING) {
                    // The date is stored as a string that needs to be parsed
                    NSString *dateString = [[NSString alloc] initWithBytes:str_ptr length:str_length encoding:NSASCIIStringEncoding];
                    creationDate = [formatter dateFromString:dateString];
                    NSLog(@"creationDate:%@",creationDate);
                }
                break;

            case 19:
                //Original Application Version
                str_ptr = ptr;
                ASN1_get_object(&str_ptr, &str_length, &str_type, &str_xclass, seq_end - str_ptr);
                if (str_type == V_ASN1_UTF8STRING) {
                    // We store the decoded string for later
                    originalVersionString = [[NSString alloc] initWithBytes:str_ptr length:str_length encoding:NSUTF8StringEncoding];
                    NSLog(@"originalVersionString:%@",originalVersionString);
                }
                break;
            case 17:
                str_ptr = ptr;
                ASN1_get_object(&str_ptr, &str_length, &str_type, &str_xclass, seq_end - str_ptr);
                if (str_type != V_ASN1_SET) {
                    // Validation fails
                    NSLog(@"str_type != V_ASN1_SET");
                }
                NSLog(@"enumerate in_app parse begin");
                while (str_ptr < seq_end) {
                    ASN1_INTEGER *small_integer;
                    // Parse the attribute sequence (a SEQUENCE is expected)
                    ASN1_get_object(&str_ptr, &str_length, &str_type, &str_xclass, seq_end - str_ptr);
                    if (str_type != V_ASN1_SEQUENCE) {
                        // Validation fails
                    }
                    const unsigned char *small_seq_end = str_ptr + str_length;
                    long small_attr_type = 0;
                    long small_attr_version = 0;
                    
                    // Parse the attribute type (an INTEGER is expected)
                    ASN1_get_object(&str_ptr, &str_length, &str_type, &str_xclass, seq_end - str_ptr);
                    if (str_type != V_ASN1_INTEGER) {
                        // Validation fails
                    }
                    small_integer = c2i_ASN1_INTEGER(NULL, &str_ptr, str_length);
                    small_attr_type = ASN1_INTEGER_get(small_integer);
                    ASN1_INTEGER_free(small_integer);
                    
                    // Parse the attribute version (an INTEGER is expected)
                    ASN1_get_object(&str_ptr, &str_length, &str_type, &str_xclass, seq_end - str_ptr);
                    if (str_type != V_ASN1_INTEGER) {
                        // Validation fails
                    }
                    small_integer = c2i_ASN1_INTEGER(NULL, &str_ptr, str_length);
                    small_attr_version = ASN1_INTEGER_get(small_integer);
                    ASN1_INTEGER_free(small_integer);
                    
                    // Check the attribute value (an OCTET STRING is expected)
                    ASN1_get_object(&str_ptr, &str_length, &str_type, &str_xclass, seq_end - str_ptr);
                    if (str_type != V_ASN1_OCTET_STRING) {
                        // Validation fails
                    }
                    NSLog(@"enumerate Receipt attr type begin:%li",small_attr_type);
                    switch (small_attr_type) {
                        case 1701:
                            small_str_ptr = str_ptr;
                            ASN1_get_object(&small_str_ptr, &small_str_length, &small_str_type, &small_str_xclass, small_seq_end - small_str_ptr);
                            if (small_str_type == V_ASN1_INTEGER) {
                                NSString *UTF8String = [[NSString alloc] initWithBytes:small_str_ptr length:small_str_length encoding:NSUTF8StringEncoding];
                                NSLog(@"quantity:%@",UTF8String);
                            }

                            break;
                        case 1702:
                            small_str_ptr = str_ptr;
                            ASN1_get_object(&small_str_ptr, &small_str_length, &small_str_type, &small_str_xclass, small_seq_end - small_str_ptr);
                            if (small_str_type == V_ASN1_UTF8STRING) {
                                NSString *UTF8String = [[NSString alloc] initWithBytes:small_str_ptr length:small_str_length encoding:NSUTF8StringEncoding];
                                NSLog(@"product_id:%@",UTF8String);
                            }
                            
                            break;
                        case 1703:
                            small_str_ptr = str_ptr;
                            ASN1_get_object(&small_str_ptr, &small_str_length, &small_str_type, &small_str_xclass, small_seq_end - small_str_ptr);
                            if (small_str_type == V_ASN1_UTF8STRING) {
                                NSString *UTF8String = [[NSString alloc] initWithBytes:small_str_ptr length:small_str_length encoding:NSUTF8StringEncoding];
                                NSLog(@"transaction_id:%@",UTF8String);
                            }
                            
                            break;
                        case 1705:
                            small_str_ptr = str_ptr;
                            ASN1_get_object(&small_str_ptr, &small_str_length, &small_str_type, &small_str_xclass, small_seq_end - small_str_ptr);
                            if (small_str_type == V_ASN1_UTF8STRING) {
                                NSString *UTF8String = [[NSString alloc] initWithBytes:small_str_ptr length:small_str_length encoding:NSUTF8StringEncoding];
                                NSLog(@"original_transaction_id:%@",UTF8String);
                            }
                            
                            break;
                            
                        case 1704:
                            small_str_ptr = str_ptr;
                            ASN1_get_object(&small_str_ptr, &small_str_length, &small_str_type, &small_str_xclass, small_seq_end - small_str_ptr);
                            if (small_str_type == V_ASN1_IA5STRING) {
                                NSString *ASCIIString = [[NSString alloc] initWithBytes:small_str_ptr length:small_str_length encoding:NSASCIIStringEncoding];
                                NSLog(@"purchase_date:%@",ASCIIString);
                            }
                            break;
                            
                        case 1706:
                            small_str_ptr = str_ptr;
                            ASN1_get_object(&small_str_ptr, &small_str_length, &small_str_type, &small_str_xclass, small_seq_end - small_str_ptr);
                            if (small_str_type == V_ASN1_IA5STRING) {
                                NSString *ASCIIString = [[NSString alloc] initWithBytes:small_str_ptr length:small_str_length encoding:NSASCIIStringEncoding];
                                NSLog(@"original_purchase_date:%@",ASCIIString);
                            }
                            break;
                        case 1708:
                            small_str_ptr = str_ptr;
                            ASN1_get_object(&small_str_ptr, &small_str_length, &small_str_type, &small_str_xclass, small_seq_end - small_str_ptr);
                            if (small_str_type == V_ASN1_IA5STRING) {
                                NSString *ASCIIString = [[NSString alloc] initWithBytes:small_str_ptr length:small_str_length encoding:NSASCIIStringEncoding];
                                NSLog(@"expires_date:%@",ASCIIString);
                            }
                            break;
                        default:
                            break;
                    }
                    NSLog(@"enumerate Receipt attr type end:%li",small_attr_type);

                    // Move past the value
                    str_ptr += str_length;
                }
                NSLog(@"enumerate in_app parse end");
                break;


            default:
                break;
        }
        NSLog(@"enumerate Payload end attr type:%li",attr_type);
        
        // Move past the value
        ptr += length;
    }
    
    // Be sure that all information is present
    if (bundleIdString == nil ||
        bundleVersionString == nil ||
        opaqueData == nil ||
        hashData == nil) {
        // Validation fails
    }
//    NSLog(@"weichaotest bundleIdString:%@;\nbundleVersionString:%@;\n",bundleIdString,bundleVersionString);
//    NSLog(@"creationDate:%@",creationDate);
//    NSLog(@"expirationDate:%@",expirationDate);
//    NSLog(@"originalVersionString:%@",originalVersionString);
//    NSLog(@"opaqueData:%@",opaqueData);
//    NSLog(@"hashData:%@",hashData);
}

- (void)verifyInformation:(NSString *)bundleIdString bundleVersionString:(NSString *)bundleVersionString {
    // Check the bundle identifier
    if (![bundleIdString isEqual:@"io.objc.myapplication"]) {
        // Validation fails
    }
    
    // Check the bundle version
    if (![bundleVersionString isEqual:@"1.0"]) {
        // Validation fails
    }
}

- (NSData *)deviceGUID {
    UIDevice *device = [UIDevice currentDevice];
    NSUUID *uuid = [device identifierForVendor];
//    uuid_t uuid;
//    [identifier getUUIDBytes:uuid];
    NSData *guidData = [NSData dataWithBytes:(const void *)uuid length:16];
    return guidData;
}

- (void)hashComputationguidData:(NSData *)guidData
                     opaqueData:(NSData *)opaqueData
                   bundleIdData:(NSData *)bundleIdData
                       hashData:(NSData *)hashData {
    unsigned char hash[20];
    
    // Create a hashing context for computation
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, [guidData bytes], (size_t) [guidData length]);
    SHA1_Update(&ctx, [opaqueData bytes], (size_t) [opaqueData length]);
    SHA1_Update(&ctx, [bundleIdData bytes], (size_t) [bundleIdData length]);
    SHA1_Final(hash, &ctx);
    
    // Do the comparison
    NSData *computedHashData = [NSData dataWithBytes:hash length:20];
    if (![computedHashData isEqualToData:hashData]) {
        // Validation fails
    }
}

- (void)volumePurchaseProgram:(NSDate *)expirationDate {
    // If an expiration date is present, check it
    if (expirationDate) {
        NSDate *currentDate = [NSDate date];
        if ([expirationDate compare:currentDate] == NSOrderedAscending) {
            // Validation fails
        }
    }
}

@end
