# IPC-H264-HLS-C-SDK

This is a sample code for IP Cameras (IPC for short) that use built-in MCU to generate TS format files and upload to S3.

And the S3_Simple_Put part of this SDK can also be considered as sample for Signature V4 process when calling S3 APIs.

With this SDK, IPC vendors don't need to pay for EC2 instances that receiving the video stream and only pay for the amount of storage they use to store the video. And can playback later with dynamically generated m3u8 file.

The input parameters of this SDK inclucde AK/SK/Token for AWS S3 access, region name, bucket name and s3 object prefix (ususally the iot device certificate id). 

System requirement:
The IPC should run a linux OS inside.
Memory should be 3.5-4MB @ 5Mbps data rate. Can adjust according to the data rate when initialize the SDK.

3rd party library:
Need OpenSSL 1.1.1 to build this project.

## Design Overview

Data flow is as following

```
                          
    IPC Encoding Module
            |
            |
            v
      H264 RAW Stream
            |
            |
            v
IPC Memory Buffer (TS Format)
            |
            |
            v
         Amazon S3

```

##IPC-H264-HLS-C-SDK usage sudo code example:

1. Initialize the system

```

S3_Put_Initialize(ak, sk, token, region, bucket, prefix);

#define BUFFER_SIZE	4*1024*1024 // 4MB
if(S3_HLS_OK != S3_HLS_Initialize(BUFFER_SIZE)) {
    return FAILED;
}

```

2. Optionally set seperate frame type, frame per second etc.

User don't need to set all these parameters but can adjust these parameters according to their own demand.

```

S3_HLS_Set_FPS(30); // each second will have 30 frames

S3_HLS_Set_Segmentation_Frame(S3_HLS_H264E_NALU_SPS); // seperate files using sps frame

S3_HLS_Set_Segmentation_Frame_Count(3); // seperate file when there are 3 sps frames in each file


```

The default values of above parameters are:

FPS: 30
Segmentation_Frame: S3_HLS_H264E_NALU_SPS
Segmentation_Frame_Count: 3

3. In the main thread of processing frames

```

// Main thread for processing frames:
while(!exit) {
    // Get frames from encoding module, pStart as frame start address, uLength as length of the frame.
    if(S3_HLS_OK != S3_HLS_Put_Frame(pStart, uLength)) {
        // Put frame to buffer failed, usually this is caused by buffer full
        // Ensure IPC can connect to S3 and have good network status
        printf("[Error]: Failed to put frame to buffer!\n");
    }
}


```

4. Create a seperate thread for running upload process:

```

while(!exit) {
    S3_HLS_Write_To_S3();
}

```

5. When exit the program, do some clean up tasks

```

S3_HLS_Finalize();
S3_Put_Finalize();

```

For using IoT Core to get AK/SK/Token, please refer to below link:
https://docs.aws.amazon.com/iot/latest/developerguide/authorizing-direct-aws.html

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

