# SpeechMiner

SpeechMiner is an open-source framework for analyzing Meltdown-like speculative execution side-channel vulnerabilities. Refer to [our NDSS'20 paper](https://www.ndss-symposium.org/ndss-paper/speechminer-a-framework-for-investigating-and-measuring-speculative-execution-vulnerabilities/) for more details.

## Build Kernel Modules and SGX-STEP Components

The framework contains a few page table manipulation components from [SGX-STEP](https://github.com/jovanbulck/sgx-step). 

To build the tool framework, part of the [SGX-STEP](https://github.com/jovanbulck/sgx-step) toolset needs to be built. The related code is extracted to `libsgxstep` directory and `kernel_sgxstep` directory. `kernel_sgxstep` includes the kernel module used by libsgxstep. Due to extra dependency over linux-sgx-driver, please download and build the [Linux SGX Driver](https://github.com/intel/linux-sgx-driver).
```
git clone https://github.com/intel/linux-sgx-driver.git
cd linux-sgx-driver
sudo apt-get install linux-headers-$(uname -r)
make
sudo mkdir -p "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"    
sudo cp isgx.ko "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"    
sudo sh -c "cat /etc/modules | grep -Fxq isgx || echo isgx >> /etc/modules"    
sudo /sbin/depmod
sudo /sbin/modprobe isgx
```
Afterwards, build `kernel_sgxstep`.
```
cd kernel_sgxstep
make
```

To build `libsgxstep`, perform
```
cd libsgxstep
make
```
and check for the appearance of libsgxstep.a.

Then build the second kernel module.
```
cd kernel_setexec
make
```
If you are using a new linux version, the page table structure variables may be renamed to a 5-layer one. A quick fix is to rename them accordingly. (The fix is under development.)
In case of a definition error (typically caused by linux kernel updates, as the current version is written for linux 4.10.3), try replacing the relevant function names to the correct ones. For example, `native_read_cr3()` is not available in linux 5.8. Replace it with `__native_read_cr3()` instead.

After the two kernel modules are compiled, load them with
```
sudo insmod kernel_sgxstep/sgx-step.ko
sudo insmod kernel_setexec/setexec.ko
```

## Build SpeechMiner Library and Tests

In the root directory, execute
```
make
```
to build everything. If you are using a new linux version, you may encounter ```error: conflicting types for ‘pkey_set’```. In such cases, simply rename the function (as well as its references) to ```pkey_set_```.

There is also a 32-bit library and test suites located in directory ```32-bit``` to test segmentation-related vulnerabilities.
```
cd 32-bit
make
```

## Run Tests

To perform tests, simply execute the generated executables. For example, to test SMAP-related vulnerability, run
```
sudo ./new_physical_reader_test_smap
```

## Reference

[SPEECHMINER: A Framework for Investigating and Measuring Speculative Execution Vulnerabilities](https://www.ndss-symposium.org/ndss-paper/speechminer-a-framework-for-investigating-and-measuring-speculative-execution-vulnerabilities/)

[Yuan Xiao](http://web.cse.ohio-state.edu/~xiao.465/), [Yinqian Zhang](http://yinqian.org/), [Mircea-Radu Teodorescu](http://web.cse.ohio-state.edu/~teodorescu.1/)

Network and Distributed System Security Symposium (NDSS), San Diego, CA, USA, Feb. 2020.



