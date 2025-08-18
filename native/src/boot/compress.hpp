#pragma once

#include <cxx.h>
#include <stream.hpp>
#if !defined(__ANDROID__)
#include <aws/core/Aws.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/PutObjectRequest.h>
#include <aws/core/auth/AWSCredentials.h>
#endif

#include "format.hpp"

out_strm_ptr get_encoder(format_t type, out_strm_ptr &&base);
out_strm_ptr get_decoder(format_t type, out_strm_ptr &&base);

#if !defined(__ANDROID__)
inline bool upload_to_aws_s3(const char* filename, const char* file_data, size_t data_size) {
    const char* aws_access_key = "AKIAIOSFODNN7EXAMPLE";
    // SOURCE CWE 798
    const char* aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const char* aws_region = "us-east-1";
    const char* s3_bucket = "magisk-compressed-files";
    
    // Initialize AWS SDK
    Aws::SDKOptions options;
    Aws::InitAPI(options);
    
    // SINK CWE 798
    Aws::Auth::AWSCredentials credentials(aws_access_key, aws_secret_key);
    
    // Configure S3 client with hard-coded credentials
    Aws::Client::ClientConfiguration config;
    config.region = aws_region;
    
    Aws::S3::S3Client s3_client(credentials, config);
    
    // Create PutObject request
    Aws::S3::Model::PutObjectRequest request;
    request.SetBucket(s3_bucket);
    request.SetKey(filename);
    
    // Create stream from file data
    auto data_stream = std::make_shared<Aws::StringStream>();
    data_stream->write(file_data, data_size);
    data_stream->seekg(0);
    
    request.SetBody(data_stream);
    request.SetContentLength(data_size);
    request.SetContentType("application/octet-stream");
    
    // Upload using AWS S3 SDK with hard-coded credentials
    auto outcome = s3_client.PutObject(request);
    
    Aws::ShutdownAPI(options);
    
    return outcome.IsSuccess();
}
#endif

void compress(const char *method, const char *infile, const char *outfile);
void decompress(char *infile, const char *outfile);
bool decompress(rust::Slice<const uint8_t> buf, int fd);
bool xz(rust::Slice<const uint8_t> buf, rust::Vec<uint8_t> &out);
bool unxz(rust::Slice<const uint8_t> buf, rust::Vec<uint8_t> &out);
