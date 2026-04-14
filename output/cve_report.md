# CVE 漏洞采集报告

> 来源：`bulletin_sample.json`  共 **32** 条（去重后），涉及 **11** 个 CVE

---

## 目录

- [CVE-2026-22801](#cve202622801)  `third_party_libpng` 中危  （3 个函数）
- [CVE-2026-22695](#cve202622695)  `third_party_libpng` 中危  （1 个函数）
- [CVE-2025-66293](#cve202566293)  `third_party_libpng` 高危  （4 个函数）
- [CVE-2025-65018](#cve202565018)  `third_party_libpng` 无  （3 个函数）
- [CVE-2025-64720](#cve202564720)  `third_party_libpng` 无  （6 个函数）
- [CVE-2025-64505](#cve202564505)  `third_party_libpng` 无  （3 个函数）
- [CVE-2025-39902](#cve202539902)  `kernel_linux_5.10` 无  （1 个函数）
- [CVE-2025-39756](#cve202539756)  `kernel_linux_5.10` 无  （1 个函数）
- [CVE-2025-12726](#cve202512726)  `chromium_src` 中危  （7 个函数）
- [CVE-2025-10200](#cve202510200)  `chromium_src` 高危  （2 个函数）
- [CVE-2022-50266](#cve202250266)  `kernel_linux_5.10` 无  （1 个函数）

---

<a id="cve202622801"></a>

## CVE-2026-22801  ·  third_party_libpng  ·  中危

**参考链接**：<https://gitcode.com/openharmony/third_party_libpng/blob/383fc00687346e9750112f62382fd93b2c6ab79f/CVE-2026-22801.patch>

**标题**：update: 更新文件 install.py

**漏洞描述**：

> Signed-off-by: gcw_5Q40SBlf <guokuan1@h-partners.com>


共涉及 **3** 个函数／代码区域：

### 1. `png_write_image_16bit(png_voidp argument)`

**文件**：`pngwrite.c`  |  **变更**：+1 / -1 行  |  ✅ 完整函数体（源文件已获取）

**Hunk 位置**：`@@ -1622,7 +1622,7 @@ png_write_image_16bit(png_voidp argument)`


#### 漏洞函数（修复前）

```c
/* patch context - source file unavailable */
/* ... line 1622 ... */
 1622        }
 1623  
 1624        png_write_row(png_ptr, png_voidcast(png_const_bytep, display->local_row));
 1625        input_row += (png_uint_16)display->row_bytes/(sizeof (png_uint_16));
 1626     }
 1627  
 1628     return 1;
```


#### 修复函数（修复后）

```c
/* patch context - source file unavailable */
/* ... line 1622 ... */
 1622        }
 1623  
 1624        png_write_row(png_ptr, png_voidcast(png_const_bytep, display->local_row));
 1625        input_row += display->row_bytes / 2;
 1626     }
 1627  
 1628     return 1;
```


#### 关键变更行

```diff
-       input_row += (png_uint_16)display->row_bytes/(sizeof (png_uint_16));
+       input_row += display->row_bytes / 2;
```


---

### 2. `png_write_image_8bit(png_voidp argument)`

**文件**：`pngwrite.c`  |  **变更**：+2 / -2 行  |  ✅ 完整函数体（源文件已获取）

**Hunk 位置**：`@@ -1748,7 +1748,7 @@ png_write_image_8bit(png_voidp argument)`、`@@ -1773,7 +1773,7 @@ png_write_image_8bit(png_voidp argument)`


#### 漏洞函数（修复前）

```c
/* patch context - source file unavailable */
/* ... line 1748 ... */
 1748  
 1749           png_write_row(png_ptr, png_voidcast(png_const_bytep,
 1750               display->local_row));
 1751           input_row += (png_uint_16)display->row_bytes/(sizeof (png_uint_16));
 1752        } /* while y */
 1753     }
 1754  
/* ... line 1773 ... */
 1773           }
 1774  
 1775           png_write_row(png_ptr, output_row);
 1776           input_row += (png_uint_16)display->row_bytes/(sizeof (png_uint_16));
 1777        }
 1778     }
 1779
```


#### 修复函数（修复后）

```c
/* patch context - source file unavailable */
/* ... line 1748 ... */
 1748  
 1749           png_write_row(png_ptr, png_voidcast(png_const_bytep,
 1750               display->local_row));
 1751           input_row += display->row_bytes / 2;
 1752        } /* while y */
 1753     }
 1754  
/* ... line 1773 ... */
 1773           }
 1774  
 1775           png_write_row(png_ptr, output_row);
 1776           input_row += display->row_bytes / 2;
 1777        }
 1778     }
 1779
```


#### 关键变更行

```diff
-          input_row += (png_uint_16)display->row_bytes/(sizeof (png_uint_16));
-          input_row += (png_uint_16)display->row_bytes/(sizeof (png_uint_16));
+          input_row += display->row_bytes / 2;
+          input_row += display->row_bytes / 2;
```


---

### 3. `png_image_write_main(png_voidp argument)`

**文件**：`pngwrite.c`  |  **变更**：+1 / -2 行  |  ✅ 完整函数体（源文件已获取）

**Hunk 位置**：`@@ -2092,7 +2092,7 @@ png_image_write_main(png_voidp argument)`


#### 漏洞函数（修复前）

```c
/* patch context - source file unavailable */
/* ... line 2092 ... */
 2092        ptrdiff_t row_bytes = display->row_stride;
 2093  
 2094        if (linear != 0)
 2095           row_bytes *= (sizeof (png_uint_16));
 2096  
 2097        if (row_bytes < 0)
 2098           row += (image->height-1) * (-row_bytes);
 2099  -
```


#### 修复函数（修复后）

```c
/* patch context - source file unavailable */
/* ... line 2092 ... */
 2092        ptrdiff_t row_bytes = display->row_stride;
 2093  
 2094        if (linear != 0)
 2095           row_bytes *= 2;
 2096  
 2097        if (row_bytes < 0)
 2098           row += (image->height-1) * (-row_bytes);
```


#### 关键变更行

```diff
-          row_bytes *= (sizeof (png_uint_16));
- - 
+          row_bytes *= 2;
```


---

<a id="cve202622695"></a>

## CVE-2026-22695  ·  third_party_libpng  ·  中危

**参考链接**：<https://gitcode.com/openharmony/third_party_libpng/blob/383fc00687346e9750112f62382fd93b2c6ab79f/CVE-2026-22695.patch>

**标题**：update: 更新文件 install.py

**漏洞描述**：

> Signed-off-by: gcw_5Q40SBlf <guokuan1@h-partners.com>


共涉及 **1** 个函数／代码区域：

### 1. `png_image_read_direct_scaled(png_voidp argument)`

**文件**：`pngread.c`  |  **变更**：+3 / -2 行  |  ✅ 完整函数体（源文件已获取）

**Hunk 位置**：`@@ -3268,9 +3268,11 @@ png_image_read_direct_scaled(png_voidp argument)`、`@@ -3300,7 +3302,7 @@ png_image_read_direct_scaled(png_voidp argument)`


#### 漏洞函数（修复前）

```c
/* patch context - source file unavailable */
/* ... line 3268 ... */
 3268         argument);
 3269     png_imagep image = display->image;
 3270     png_structrp png_ptr = image->opaque->png_ptr;
 3271     png_bytep local_row = png_voidcast(png_bytep, display->local_row);
 3272     png_bytep first_row = png_voidcast(png_bytep, display->first_row);
 3273     ptrdiff_t row_bytes = display->row_bytes;
 3274     int passes;
 3275  
 3276     /* Handle interlacing. */
/* ... line 3300 ... */
 3300           png_read_row(png_ptr, local_row, NULL);
 3301  
 3302           /* Copy from local_row to user buffer. */
 3303           memcpy(output_row, local_row, (size_t)row_bytes);
 3304           output_row += row_bytes;
 3305        }
 3306     }
 3307  -
```


#### 修复函数（修复后）

```c
/* patch context - source file unavailable */
/* ... line 3268 ... */
 3268         argument);
 3269     png_imagep image = display->image;
 3270     png_structrp png_ptr = image->opaque->png_ptr;
 3271     png_inforp info_ptr = image->opaque->info_ptr;
 3272     png_bytep local_row = png_voidcast(png_bytep, display->local_row);
 3273     png_bytep first_row = png_voidcast(png_bytep, display->first_row);
 3274     ptrdiff_t row_bytes = display->row_bytes;
 3275     size_t copy_bytes = png_get_rowbytes(png_ptr, info_ptr);
 3276     int passes;
 3277  
 3278     /* Handle interlacing. */
/* ... line 3302 ... */
 3302           png_read_row(png_ptr, local_row, NULL);
 3303  
 3304           /* Copy from local_row to user buffer. */
 3305           memcpy(output_row, local_row, copy_bytes);
 3306           output_row += row_bytes;
 3307        }
 3308     }
```


#### 关键变更行

```diff
-          memcpy(output_row, local_row, (size_t)row_bytes);
- - 
+    png_inforp info_ptr = image->opaque->info_ptr;
+    size_t copy_bytes = png_get_rowbytes(png_ptr, info_ptr);
+          memcpy(output_row, local_row, copy_bytes);
```


---

<a id="cve202566293"></a>

## CVE-2025-66293  ·  third_party_libpng  ·  高危

**参考链接**：<https://gitcode.com/openharmony/third_party_libpng/pull/90>

**标题**：new: 新建文件 CVE-2025-65018.patch

**漏洞描述**：

> Signed-off-by: gcw_5Q40SBlf <guokuan1@h-partners.com>


共涉及 **4** 个函数／代码区域：

### 1. `def move_file(src_path, dst_path):`

**文件**：`install.py`  |  **变更**：+3 / -1 行  |  ⚠️ 仅 diff 上下文（源文件不可用，代码不完整）

**Hunk 位置**：`@@ -42,7 +42,9 @@ def move_file(src_path, dst_path):`


#### 代码变更（diff 上下文，源文件不可用）

```diff
-         "CVE-2025-65018.patch"
+         "CVE-2025-65018.patch",
+         "CVE-2025-66293.patch",
+         "CVE-2025-66293-h1.patch"
```

<details><summary>修复前上下文窗口（展开）</summary>

```python
/* patch context - source file unavailable */
/* ... line 42 ... */
   42          "CVE-2025-64505.patch",
   43          "CVE-2025-64506.patch",
   44          "CVE-2025-64720.patch",
   45          "CVE-2025-65018.patch"
   46      ]
   47      for file in files:
   48          src_file = os.path.join(src_path, file)
```

</details>

<details><summary>修复后上下文窗口（展开）</summary>

```python
/* patch context - source file unavailable */
/* ... line 42 ... */
   42          "CVE-2025-64505.patch",
   43          "CVE-2025-64506.patch",
   44          "CVE-2025-64720.patch",
   45          "CVE-2025-65018.patch",
   46          "CVE-2025-66293.patch",
   47          "CVE-2025-66293-h1.patch"
   48      ]
   49      for file in files:
   50          src_file = os.path.join(src_path, file)
```

</details>


---

### 2. `def do_patch(target_dir):`

**文件**：`install.py`  |  **变更**：+3 / -1 行  |  ⚠️ 仅 diff 上下文（源文件不可用，代码不完整）

**Hunk 位置**：`@@ -72,7 +74,9 @@ def do_patch(target_dir):`


#### 代码变更（diff 上下文，源文件不可用）

```diff
-         "CVE-2025-65018.patch"
+         "CVE-2025-65018.patch",
+         "CVE-2025-66293.patch",
+         "CVE-2025-66293-h1.patch"
```

<details><summary>修复前上下文窗口（展开）</summary>

```python
/* patch context - source file unavailable */
/* ... line 72 ... */
   72          "CVE-2025-64505.patch",
   73          "CVE-2025-64506.patch",
   74          "CVE-2025-64720.patch",
   75          "CVE-2025-65018.patch"
   76      ]
   77  
   78      for patch in patch_file:
```

</details>

<details><summary>修复后上下文窗口（展开）</summary>

```python
/* patch context - source file unavailable */
/* ... line 74 ... */
   74          "CVE-2025-64505.patch",
   75          "CVE-2025-64506.patch",
   76          "CVE-2025-64720.patch",
   77          "CVE-2025-65018.patch",
   78          "CVE-2025-66293.patch",
   79          "CVE-2025-66293-h1.patch"
   80      ]
   81  
   82      for patch in patch_file:
```

</details>


---

### 3. `png_image_read_colormapped(png_voidp argument)`

**文件**：`pngread.c`  |  **变更**：+48 / -0 行  |  ✅ 完整函数体（源文件已获取）

**Hunk 位置**：`@@ -3521,6 +3521,54 @@ png_image_read_colormapped(png_voidp argument)`


#### 漏洞函数（修复前）

```c
/* patch context - source file unavailable */
/* ... line 3521 ... */
 3521     }
 3522  }
 3523  
 3524  /* Just the row reading part of png_image_read. */
 3525  static int
 3526  png_image_read_composite(png_voidp argument)
```


#### 修复函数（修复后）

```c
/* patch context - source file unavailable */
/* ... line 3521 ... */
 3521     }
 3522  }
 3523  
 3524  /* Row reading for interlaced 16-to-8 bit depth conversion with local buffer. */
 3525  static int
 3526  png_image_read_direct_scaled(png_voidp argument)
 3527  {
 3528     png_image_read_control *display = png_voidcast(png_image_read_control*,
 3529         argument);
 3530     png_imagep image = display->image;
 3531     png_structrp png_ptr = image->opaque->png_ptr;
 3532     png_bytep local_row = png_voidcast(png_bytep, display->local_row);
 3533     png_bytep first_row = png_voidcast(png_bytep, display->first_row);
 3534     ptrdiff_t row_bytes = display->row_bytes;
 3535     int passes;
 3536  
 3537     /* Handle interlacing. */
 3538     switch (png_ptr->interlaced)
 3539     {
 3540        case PNG_INTERLACE_NONE:
 3541           passes = 1;
 3542           break;
 3543  
 3544        case PNG_INTERLACE_ADAM7:
 3545           passes = PNG_INTERLACE_ADAM7_PASSES;
 3546           break;
 3547  
 3548        default:
 3549           png_error(png_ptr, "unknown interlace type");
 3550     }
 3551  
 3552     /* Read each pass using local_row as intermediate buffer. */
 3553     while (--passes >= 0)
 3554     {
 3555        png_uint_32 y = image->height;
 3556        png_bytep output_row = first_row;
 3557  
 3558        for (; y > 0; --y)
 3559        {
 3560           /* Read into local_row (gets transformed 8-bit data). */
 3561           png_read_row(png_ptr, local_row, NULL);
 3562  
 3563           /* Copy from local_row to user buffer. */
 3564           memcpy(output_row, local_row, (size_t)row_bytes);
 3565           output_row += row_bytes;
 3566        }
 3567     }
 3568  
 3569     return 1;
 3570  }
 3571  
 3572  /* Just the row reading part of png_image_read. */
 3573  static int
 3574  png_image_read_composite(png_voidp argument)
```


#### 关键变更行

```diff
+ /* Row reading for interlaced 16-to-8 bit depth conversion with local buffer. */
+ static int
+ png_image_read_direct_scaled(png_voidp argument)
+ {
+    png_image_read_control *display = png_voidcast(png_image_read_control*,
+        argument);
+    png_imagep image = display->image;
+    png_structrp png_ptr = image->opaque->png_ptr;
+    png_bytep local_row = png_voidcast(png_bytep, display->local_row);
+    png_bytep first_row = png_voidcast(png_bytep, display->first_row);
+    ptrdiff_t row_bytes = display->row_bytes;
+    int passes;
+ 
+    /* Handle interlacing. */
+    switch (png_ptr->interlaced)
+    {
+       case PNG_INTERLACE_NONE:
+          passes = 1;
+          break;
+ 
+       case PNG_INTERLACE_ADAM7:
+          passes = PNG_INTERLACE_ADAM7_PASSES;
+          break;
+ 
+       default:
+          png_error(png_ptr, "unknown interlace type");
+    }
+ 
+    /* Read each pass using local_row as intermediate buffer. */
+    while (--passes >= 0)
+    {
+       png_uint_32 y = image->height;
+       png_bytep output_row = first_row;
+ 
+       for (; y > 0; --y)
+       {
+          /* Read into local_row (gets transformed 8-bit data). */
+          png_read_row(png_ptr, local_row, NULL);
+ 
+          /* Copy from local_row to user buffer. */
+          memcpy(output_row, local_row, (size_t)row_bytes);
+          output_row += row_bytes;
+       }
+    }
+ 
+    return 1;
+ }
+ 
```


---

### 4. `png_image_read_direct(png_voidp argument)`

**文件**：`pngread.c`  |  **变更**：+27 / -1 行  |  ✅ 完整函数体（源文件已获取）

**Hunk 位置**：`@@ -3942,6 +3990,7 @@ png_image_read_direct(png_voidp argument)`、`@@ -4068,8 +4117,16 @@ png_image_read_direct(png_voidp argument)`、`@@ -4345,6 +4402,24 @@ png_image_read_direct(png_voidp argument)`


#### 漏洞函数（修复前）

```c
/* patch context - source file unavailable */
/* ... line 3942 ... */
 3942     int linear = (format & PNG_FORMAT_FLAG_LINEAR) != 0;
 3943     int do_local_compose = 0;
 3944     int do_local_background = 0; /* to avoid double gamma correction bug */
 3945     int passes = 0;
 3946  
 3947     /* Add transforms to ensure the correct output format is produced then check
/* ... line 4068 ... */
 4068              png_set_expand_16(png_ptr);
 4069  
 4070           else /* 8-bit output */
 4071              png_set_scale_16(png_ptr);
 4072  
 4073           change &= ~PNG_FORMAT_FLAG_LINEAR;
 4074        }
 4075  
/* ... line 4345 ... */
 4345        return result;
 4346     }
 4347  
 4348     else
 4349     {
 4350        png_alloc_size_t row_bytes = (png_alloc_size_t)display->row_bytes;
 4351  -
```


#### 修复函数（修复后）

```c
/* patch context - source file unavailable */
/* ... line 3990 ... */
 3990     int linear = (format & PNG_FORMAT_FLAG_LINEAR) != 0;
 3991     int do_local_compose = 0;
 3992     int do_local_background = 0; /* to avoid double gamma correction bug */
 3993     int do_local_scale = 0; /* for interlaced 16-to-8 bit conversion */
 3994     int passes = 0;
 3995  
 3996     /* Add transforms to ensure the correct output format is produced then check
/* ... line 4117 ... */
 4117              png_set_expand_16(png_ptr);
 4118  
 4119           else /* 8-bit output */
 4120           {
 4121              png_set_scale_16(png_ptr);
 4122  
 4123              /* For interlaced images, use local_row buffer to avoid overflow
 4124               * in png_combine_row() which writes using IHDR bit-depth.
 4125               */
 4126              if (png_ptr->interlaced != 0)
 4127                 do_local_scale = 1;
 4128           }
 4129  
 4130           change &= ~PNG_FORMAT_FLAG_LINEAR;
 4131        }
 4132  
/* ... line 4402 ... */
 4402        return result;
 4403     }
 4404  
 4405     else if (do_local_scale != 0)
 4406     {
 4407        /* For interlaced 16-to-8 conversion, use an intermediate row buffer
 4408         * to avoid buffer overflows in png_combine_row. The local_row is sized
 4409         * for the transformed (8-bit) output, preventing the overflow that would
 4410         * occur if png_combine_row wrote 16-bit data directly to the user buffer.
 4411         */
 4412        int result;
 4413        png_voidp row = png_malloc(png_ptr, png_get_rowbytes(png_ptr, info_ptr));
 4414  
 4415        display->local_row = row;
 4416        result = png_safe_execute(image, png_image_read_direct_scaled, display);
 4417        display->local_row = NULL;
 4418        png_free(png_ptr, row);
 4419  
 4420        return result;
 4421     }
 4422  
 4423     else
 4424     {
 4425        png_alloc_size_t row_bytes = (png_alloc_size_t)display->row_bytes;
```


#### 关键变更行

```diff
- - 
+    int do_local_scale = 0; /* for interlaced 16-to-8 bit conversion */
+          {
+             /* For interlaced images, use local_row buffer to avoid overflow
+              * in png_combine_row() which writes using IHDR bit-depth.
+              */
+             if (png_ptr->interlaced != 0)
+                do_local_scale = 1;
+          }
+ 
+    else if (do_local_scale != 0)
+    {
+       /* For interlaced 16-to-8 conversion, use an intermediate row buffer
+        * to avoid buffer overflows in png_combine_row. The local_row is sized
+        * for the transformed (8-bit) output, preventing the overflow that would
+        * occur if png_combine_row wrote 16-bit data directly to the user buffer.
+        */
+       int result;
+       png_voidp row = png_malloc(png_ptr, png_get_rowbytes(png_ptr, info_ptr));
+ 
+       display->local_row = row;
+       result = png_safe_execute(image, png_image_read_direct_scaled, display);
+       display->local_row = NULL;
+       png_free(png_ptr, row);
+ 
+       return result;
+    }
+ 
```


---

<a id="cve202565018"></a>

## CVE-2025-65018  ·  third_party_libpng  ·  无

**参考链接**：<https://gitcode.com/openharmony/third_party_libpng/blob/d5bb6e40a0c0a2b1b388b122f85b7632dbd58fdc/CVE-2025-65018.patch>

**标题**：漏洞修复CVE-2025-64505、CVE-2025-64506、CVE-2025-64720、CVE-2025-65018

**漏洞描述**：

> Signed-off-by: zhwang0 <zhwang0@163.com>


共涉及 **3** 个函数／代码区域：

### 1. `png_image_read_colormapped(png_voidp argument)`

**文件**：`pngread.c`  |  **变更**：+48 / -0 行  |  ✅ 完整函数体（源文件已获取）

**Hunk 位置**：`@@ -3521,6 +3521,54 @@ png_image_read_colormapped(png_voidp argument)`


#### 漏洞函数（修复前）

```c
/* patch context - source file unavailable */
/* ... line 3521 ... */
 3521     }
 3522  }
 3523  
 3524  /* Just the row reading part of png_image_read. */
 3525  static int
 3526  png_image_read_composite(png_voidp argument)
```


#### 修复函数（修复后）

```c
/* patch context - source file unavailable */
/* ... line 3521 ... */
 3521     }
 3522  }
 3523  
 3524  /* Row reading for interlaced 16-to-8 bit depth conversion with local buffer. */
 3525  static int
 3526  png_image_read_direct_scaled(png_voidp argument)
 3527  {
 3528     png_image_read_control *display = png_voidcast(png_image_read_control*,
 3529         argument);
 3530     png_imagep image = display->image;
 3531     png_structrp png_ptr = image->opaque->png_ptr;
 3532     png_bytep local_row = png_voidcast(png_bytep, display->local_row);
 3533     png_bytep first_row = png_voidcast(png_bytep, display->first_row);
 3534     ptrdiff_t row_bytes = display->row_bytes;
 3535     int passes;
 3536  
 3537     /* Handle interlacing. */
 3538     switch (png_ptr->interlaced)
 3539     {
 3540        case PNG_INTERLACE_NONE:
 3541           passes = 1;
 3542           break;
 3543  
 3544        case PNG_INTERLACE_ADAM7:
 3545           passes = PNG_INTERLACE_ADAM7_PASSES;
 3546           break;
 3547  
 3548        default:
 3549           png_error(png_ptr, "unknown interlace type");
 3550     }
 3551  
 3552     /* Read each pass using local_row as intermediate buffer. */
 3553     while (--passes >= 0)
 3554     {
 3555        png_uint_32 y = image->height;
 3556        png_bytep output_row = first_row;
 3557  
 3558        for (; y > 0; --y)
 3559        {
 3560           /* Read into local_row (gets transformed 8-bit data). */
 3561           png_read_row(png_ptr, local_row, NULL);
 3562  
 3563           /* Copy from local_row to user buffer. */
 3564           memcpy(output_row, local_row, (size_t)row_bytes);
 3565           output_row += row_bytes;
 3566        }
 3567     }
 3568  
 3569     return 1;
 3570  }
 3571  
 3572  /* Just the row reading part of png_image_read. */
 3573  static int
 3574  png_image_read_composite(png_voidp argument)
```


#### 关键变更行

```diff
+ /* Row reading for interlaced 16-to-8 bit depth conversion with local buffer. */
+ static int
+ png_image_read_direct_scaled(png_voidp argument)
+ {
+    png_image_read_control *display = png_voidcast(png_image_read_control*,
+        argument);
+    png_imagep image = display->image;
+    png_structrp png_ptr = image->opaque->png_ptr;
+    png_bytep local_row = png_voidcast(png_bytep, display->local_row);
+    png_bytep first_row = png_voidcast(png_bytep, display->first_row);
+    ptrdiff_t row_bytes = display->row_bytes;
+    int passes;
+ 
+    /* Handle interlacing. */
+    switch (png_ptr->interlaced)
+    {
+       case PNG_INTERLACE_NONE:
+          passes = 1;
+          break;
+ 
+       case PNG_INTERLACE_ADAM7:
+          passes = PNG_INTERLACE_ADAM7_PASSES;
+          break;
+ 
+       default:
+          png_error(png_ptr, "unknown interlace type");
+    }
+ 
+    /* Read each pass using local_row as intermediate buffer. */
+    while (--passes >= 0)
+    {
+       png_uint_32 y = image->height;
+       png_bytep output_row = first_row;
+ 
+       for (; y > 0; --y)
+       {
+          /* Read into local_row (gets transformed 8-bit data). */
+          png_read_row(png_ptr, local_row, NULL);
+ 
+          /* Copy from local_row to user buffer. */
+          memcpy(output_row, local_row, (size_t)row_bytes);
+          output_row += row_bytes;
+       }
+    }
+ 
+    return 1;
+ }
+ 
```


---

### 2. `png_image_read_direct(png_voidp argument)`

**文件**：`pngread.c`  |  **变更**：+27 / -1 行  |  ✅ 完整函数体（源文件已获取）

**Hunk 位置**：`@@ -3942,6 +3990,7 @@ png_image_read_direct(png_voidp argument)`、`@@ -4068,8 +4117,16 @@ png_image_read_direct(png_voidp argument)`、`@@ -4345,6 +4402,24 @@ png_image_read_direct(png_voidp argument)`


#### 漏洞函数（修复前）

```c
/* patch context - source file unavailable */
/* ... line 3942 ... */
 3942     int linear = (format & PNG_FORMAT_FLAG_LINEAR) != 0;
 3943     int do_local_compose = 0;
 3944     int do_local_background = 0; /* to avoid double gamma correction bug */
 3945     int passes = 0;
 3946  
 3947     /* Add transforms to ensure the correct output format is produced then check
/* ... line 4068 ... */
 4068              png_set_expand_16(png_ptr);
 4069  
 4070           else /* 8-bit output */
 4071              png_set_scale_16(png_ptr);
 4072  
 4073           change &= ~PNG_FORMAT_FLAG_LINEAR;
 4074        }
 4075  
/* ... line 4345 ... */
 4345        return result;
 4346     }
 4347  
 4348     else
 4349     {
 4350        png_alloc_size_t row_bytes = (png_alloc_size_t)display->row_bytes;
 4351  -
```


#### 修复函数（修复后）

```c
/* patch context - source file unavailable */
/* ... line 3990 ... */
 3990     int linear = (format & PNG_FORMAT_FLAG_LINEAR) != 0;
 3991     int do_local_compose = 0;
 3992     int do_local_background = 0; /* to avoid double gamma correction bug */
 3993     int do_local_scale = 0; /* for interlaced 16-to-8 bit conversion */
 3994     int passes = 0;
 3995  
 3996     /* Add transforms to ensure the correct output format is produced then check
/* ... line 4117 ... */
 4117              png_set_expand_16(png_ptr);
 4118  
 4119           else /* 8-bit output */
 4120           {
 4121              png_set_scale_16(png_ptr);
 4122  
 4123              /* For interlaced images, use local_row buffer to avoid overflow
 4124               * in png_combine_row() which writes using IHDR bit-depth.
 4125               */
 4126              if (png_ptr->interlaced != 0)
 4127                 do_local_scale = 1;
 4128           }
 4129  
 4130           change &= ~PNG_FORMAT_FLAG_LINEAR;
 4131        }
 4132  
/* ... line 4402 ... */
 4402        return result;
 4403     }
 4404  
 4405     else if (do_local_scale != 0)
 4406     {
 4407        /* For interlaced 16-to-8 conversion, use an intermediate row buffer
 4408         * to avoid buffer overflows in png_combine_row. The local_row is sized
 4409         * for the transformed (8-bit) output, preventing the overflow that would
 4410         * occur if png_combine_row wrote 16-bit data directly to the user buffer.
 4411         */
 4412        int result;
 4413        png_voidp row = png_malloc(png_ptr, png_get_rowbytes(png_ptr, info_ptr));
 4414  
 4415        display->local_row = row;
 4416        result = png_safe_execute(image, png_image_read_direct_scaled, display);
 4417        display->local_row = NULL;
 4418        png_free(png_ptr, row);
 4419  
 4420        return result;
 4421     }
 4422  
 4423     else
 4424     {
 4425        png_alloc_size_t row_bytes = (png_alloc_size_t)display->row_bytes;
```


#### 关键变更行

```diff
- - 
+    int do_local_scale = 0; /* for interlaced 16-to-8 bit conversion */
+          {
+             /* For interlaced images, use local_row buffer to avoid overflow
+              * in png_combine_row() which writes using IHDR bit-depth.
+              */
+             if (png_ptr->interlaced != 0)
+                do_local_scale = 1;
+          }
+ 
+    else if (do_local_scale != 0)
+    {
+       /* For interlaced 16-to-8 conversion, use an intermediate row buffer
+        * to avoid buffer overflows in png_combine_row. The local_row is sized
+        * for the transformed (8-bit) output, preventing the overflow that would
+        * occur if png_combine_row wrote 16-bit data directly to the user buffer.
+        */
+       int result;
+       png_voidp row = png_malloc(png_ptr, png_get_rowbytes(png_ptr, info_ptr));
+ 
+       display->local_row = row;
+       result = png_safe_execute(image, png_image_read_direct_scaled, display);
+       display->local_row = NULL;
+       png_free(png_ptr, row);
+ 
+       return result;
+    }
+ 
```


---

### 3. `png_init_read_transformations(png_structrp png_ptr)`

**文件**：`pngrtran.c`  |  **变更**：+45 / -14 行  |  ✅ 完整函数体（源文件已获取）

**Hunk 位置**：`@@ -1699,19 +1699,51 @@ png_init_read_transformations(png_structrp png_ptr)`


#### 漏洞函数（修复前）

```c
void /* PRIVATE */
png_init_read_transformations(png_structrp png_ptr)
{
   png_debug(1, "in png_init_read_transformations");

   /* This internal function is called from png_read_start_row in pngrutil.c
    * and it is called before the 'rowbytes' calculation is done, so the code
    * in here can change or update the transformations flags.
    *
    * First do updates that do not depend on the details of the PNG image data
    * being processed.
    */

#ifdef PNG_READ_GAMMA_SUPPORTED
   /* Prior to 1.5.4 these tests were performed from png_set_gamma, 1.5.4 adds
    * png_set_alpha_mode and this is another source for a default file gamma so
    * the test needs to be performed later - here.  In addition prior to 1.5.4
    * the tests were repeated for the PALETTE color type here - this is no
    * longer necessary (and doesn't seem to have been necessary before.)
    *
    * PNGv3: the new mandatory precedence/priority rules for colour space chunks
    * are handled here (by calling the above function).
    *
    * Turn the gamma transformation on or off as appropriate.  Notice that
    * PNG_GAMMA just refers to the file->screen correction.  Alpha composition
    * may independently cause gamma correction because it needs linear data
    * (e.g. if the file has a gAMA chunk but the screen gamma hasn't been
    * specified.)  In any case this flag may get turned off in the code
    * immediately below if the transform can be handled outside the row loop.
    */
   if (png_init_gamma_values(png_ptr) != 0)
      png_ptr->transformations |= PNG_GAMMA;

   else
      png_ptr->transformations &= ~PNG_GAMMA;
#endif

   /* Certain transformations have the effect of preventing other
    * transformations that happen afterward in png_do_read_transformations;
    * resolve the interdependencies here.  From the code of
    * png_do_read_transformations the order is:
    *
    *  1) PNG_EXPAND (including PNG_EXPAND_tRNS)
    *  2) PNG_STRIP_ALPHA (if no compose)
    *  3) PNG_RGB_TO_GRAY
    *  4) PNG_GRAY_TO_RGB iff !PNG_BACKGROUND_IS_GRAY
    *  5) PNG_COMPOSE
    *  6) PNG_GAMMA
    *  7) PNG_STRIP_ALPHA (if compose)
    *  8) PNG_ENCODE_ALPHA
    *  9) PNG_SCALE_16_TO_8
    * 10) PNG_16_TO_8
    * 11) PNG_QUANTIZE (converts to palette)
    * 12) PNG_EXPAND_16
    * 13) PNG_GRAY_TO_RGB iff PNG_BACKGROUND_IS_GRAY
    * 14) PNG_INVERT_MONO
    * 15) PNG_INVERT_ALPHA
    * 16) PNG_SHIFT
    * 17) PNG_PACK
    * 18) PNG_BGR
    * 19) PNG_PACKSWAP
    * 20) PNG_FILLER (includes PNG_ADD_ALPHA)
    * 21) PNG_SWAP_ALPHA
    * 22) PNG_SWAP_BYTES
    * 23) PNG_USER_TRANSFORM [must be last]
    */
#ifdef PNG_READ_STRIP_ALPHA_SUPPORTED
   if ((png_ptr->transformations & PNG_STRIP_ALPHA) != 0 &&
       (png_ptr->transformations & PNG_COMPOSE) == 0)
   {
      /* Stripping the alpha channel happens immediately after the 'expand'
       * transformations, before all other transformation, so it cancels out
       * the alpha handling.  It has the side effect negating the effect of
       * PNG_EXPAND_tRNS too:
       */
      png_ptr->transformations &= ~(PNG_BACKGROUND_EXPAND | PNG_ENCODE_ALPHA |
         PNG_EXPAND_tRNS);
      png_ptr->flags &= ~PNG_FLAG_OPTIMIZE_ALPHA;

      /* Kill the tRNS chunk itself too.  Prior to 1.5.4 this did not happen
       * so transparency information would remain just so long as it wasn't
       * expanded.  This produces unexpected API changes if the set of things
       * that do PNG_EXPAND_tRNS changes (perfectly possible given the
       * documentation - which says ask for what you want, accept what you
       * get.)  This makes the behavior consistent from 1.5.4:
       */
      png_ptr->num_trans = 0;
   }
#endif /* STRIP_ALPHA supported, no COMPOSE */

#ifdef PNG_READ_ALPHA_MODE_SUPPORTED
   /* If the screen gamma is about 1.0 then the OPTIMIZE_ALPHA and ENCODE_ALPHA
    * settings will have no effect.
    */
   if (png_gamma_significant(png_ptr->screen_gamma) == 0)
   {
      png_ptr->transformations &= ~PNG_ENCODE_ALPHA;
      png_ptr->flags &= ~PNG_FLAG_OPTIMIZE_ALPHA;
   }
#endif

#ifdef PNG_READ_RGB_TO_GRAY_SUPPORTED
   /* Make sure the coefficients for the rgb to gray conversion are set
    * appropriately.
    */
   if ((png_ptr->transformations & PNG_RGB_TO_GRAY) != 0)
      png_set_rgb_coefficients(png_ptr);
#endif

#ifdef PNG_READ_GRAY_TO_RGB_SUPPORTED
#if defined(PNG_READ_EXPAND_SUPPORTED) && defined(PNG_READ_BACKGROUND_SUPPORTED)
   /* Detect gray background and attempt to enable optimization for
    * gray --> RGB case.
    *
    * Note:  if PNG_BACKGROUND_EXPAND is set and color_type is either RGB or
    * RGB_ALPHA (in which case need_expand is superfluous anyway), the
    * background color might actually be gray yet not be flagged as such.
    * This is not a problem for the current code, which uses
    * PNG_BACKGROUND_IS_GRAY only to decide when to do the
    * png_do_gray_to_rgb() transformation.
    *
    * TODO: this code needs to be revised to avoid the complexity and
    * interdependencies.  The color type of the background should be recorded in
    * png_set_background, along with the bit depth, then the code has a record
    * of exactly what color space the background is currently in.
    */
   if ((png_ptr->transformations & PNG_BACKGROUND_EXPAND) != 0)
   {
      /* PNG_BACKGROUND_EXPAND: the background is in the file color space, so if
       * the file was grayscale the background value is gray.
       */
      if ((png_ptr->color_type & PNG_COLOR_MASK_COLOR) == 0)
         png_ptr->mode |= PNG_BACKGROUND_IS_GRAY;
   }

   else if ((png_ptr->transformations & PNG_COMPOSE) != 0)
   {
      /* PNG_COMPOSE: png_set_background was called with need_expand false,
       * so the color is in the color space of the output or png_set_alpha_mode
       * was called and the color is black.  Ignore RGB_TO_GRAY because that
       * happens before GRAY_TO_RGB.
       */
      if ((png_ptr->transformations & PNG_GRAY_TO_RGB) != 0)
      {
         if (png_ptr->background.red == png_ptr->background.green &&
             png_ptr->background.red == png_ptr->background.blue)
         {
            png_ptr->mode |= PNG_BACKGROUND_IS_GRAY;
            png_ptr->background.gray = png_ptr->background.red;
         }
      }
   }
#endif /* READ_EXPAND && READ_BACKGROUND */
#endif /* READ_GRAY_TO_RGB */

   /* For indexed PNG data (PNG_COLOR_TYPE_PALETTE) many of the transformations
    * can be performed directly on the palette, and some (such as rgb to gray)
    * can be optimized inside the palette.  This is particularly true of the
    * composite (background and alpha) stuff, which can be pretty much all done
    * in the palette even if the result is expanded to RGB or gray afterward.
    *
    * NOTE: this is Not Yet Implemented, the code behaves as in 1.5.1 and
    * earlier and the palette stuff is actually handled on the first row.  This
    * leads to the reported bug that the palette returned by png_get_PLTE is not
    * updated.
    */
   if (png_ptr->color_type == PNG_COLOR_TYPE_PALETTE)
      png_init_palette_transformations(png_ptr);

   else
      png_init_rgb_transformations(png_ptr);

#if defined(PNG_READ_BACKGROUND_SUPPORTED) && \
   defined(PNG_READ_EXPAND_16_SUPPORTED)
   if ((png_ptr->transformations & PNG_EXPAND_16) != 0 &&
       (png_ptr->transformations & PNG_COMPOSE) != 0 &&
       (png_ptr->transformations & PNG_BACKGROUND_EXPAND) == 0 &&
       png_ptr->bit_depth != 16)
   {
      /* TODO: fix this.  Because the expand_16 operation is after the compose
       * handling the background color must be 8, not 16, bits deep, but the
       * application will supply a 16-bit value so reduce it here.
       *
       * The PNG_BACKGROUND_EXPAND code above does not expand to 16 bits at
       * present, so that case is ok (until do_expand_16 is moved.)
       *
       * NOTE: this discards the low 16 bits of the user supplied background
       * color, but until expand_16 works properly there is no choice!
       */
#     define CHOP(x) (x)=((png_uint_16)PNG_DIV257(x))
      CHOP(png_ptr->background.red);
      CHOP(png_ptr->background.green);
      CHOP(png_ptr->background.blue);
      CHOP(png_ptr->background.gray);
#     undef CHOP
   }
#endif /* READ_BACKGROUND && READ_EXPAND_16 */

#if defined(PNG_READ_BACKGROUND_SUPPORTED) && \
   (defined(PNG_READ_SCALE_16_TO_8_SUPPORTED) || \
   defined(PNG_READ_STRIP_16_TO_8_SUPPORTED))
   if ((png_ptr->transformations & (PNG_16_TO_8|PNG_SCALE_16_TO_8)) != 0 &&
       (png_ptr->transformations & PNG_COMPOSE) != 0 &&
       (png_ptr->transformations & PNG_BACKGROUND_EXPAND) == 0 &&
       png_ptr->bit_depth == 16)
   {
      /* On the other hand, if a 16-bit file is to be reduced to 8-bits per
       * component this will also happen after PNG_COMPOSE and so the background
       * color must be pre-expanded here.
       *
       * TODO: fix this too.
       */
      png_ptr->background.red = (png_uint_16)(png_ptr->background.red * 257);
      png_ptr->background.green =
         (png_uint_16)(png_ptr->background.green * 257);
      png_ptr->background.blue = (png_uint_16)(png_ptr->background.blue * 257);
      png_ptr->background.gray = (png_uint_16)(png_ptr->background.gray * 257);
   }
#endif

   /* NOTE: below 'PNG_READ_ALPHA_MODE_SUPPORTED' is presumed to also enable the
    * background support (see the comments in scripts/pnglibconf.dfa), this
    * allows pre-multiplication of the alpha channel to be implemented as
    * compositing on black.  This is probably sub-optimal and has been done in
    * 1.5.4 betas simply to enable external critique and testing (i.e. to
    * implement the new API quickly, without lots of internal changes.)
    */

#ifdef PNG_READ_GAMMA_SUPPORTED
#  ifdef PNG_READ_BACKGROUND_SUPPORTED
      /* Includes ALPHA_MODE */
      png_ptr->background_1 = png_ptr->background;
#  endif

   /* This needs to change - in the palette image case a whole set of tables are
    * built when it would be quicker to just calculate the correct value for
    * each palette entry directly.  Also, the test is too tricky - why check
    * PNG_RGB_TO_GRAY if PNG_GAMMA is not set?  The answer seems to be that
    * PNG_GAMMA is cancelled even if the gamma is known?  The test excludes the
    * PNG_COMPOSE case, so apparently if there is no *overall* gamma correction
    * the gamma tables will not be built even if composition is required on a
    * gamma encoded value.
    *
    * In 1.5.4 this is addressed below by an additional check on the individual
    * file gamma - if it is not 1.0 both RGB_TO_GRAY and COMPOSE need the
    * tables.
    */
   if ((png_ptr->transformations & PNG_GAMMA) != 0 ||
       ((png_ptr->transformations & PNG_RGB_TO_GRAY) != 0 &&
        (png_gamma_significant(png_ptr->file_gamma) != 0 ||
         png_gamma_significant(png_ptr->screen_gamma) != 0)) ||
        ((png_ptr->transformations & PNG_COMPOSE) != 0 &&
         (png_gamma_significant(png_ptr->file_gamma) != 0 ||
          png_gamma_significant(png_ptr->screen_gamma) != 0
#  ifdef PNG_READ_BACKGROUND_SUPPORTED
         || (png_ptr->background_gamma_type == PNG_BACKGROUND_GAMMA_UNIQUE &&
           png_gamma_significant(png_ptr->background_gamma) != 0)
#  endif
        )) || ((png_ptr->transformations & PNG_ENCODE_ALPHA) != 0 &&
       png_gamma_significant(png_ptr->screen_gamma) != 0))
   {
      png_build_gamma_table(png_ptr, png_ptr->bit_depth);

#ifdef PNG_READ_BACKGROUND_SUPPORTED
      if ((png_ptr->transformations & PNG_COMPOSE) != 0)
      {
         /* Issue a warning about this combination: because RGB_TO_GRAY is
          * optimized to do the gamma transform if present yet do_background has
          * to do the same thing if both options are set a
          * double-gamma-correction happens.  This is true in all versions of
          * libpng to date.
          */
         if ((png_ptr->transformations & PNG_RGB_TO_GRAY) != 0)
            png_warning(png_ptr,
                "libpng does not support gamma+background+rgb_to_gray");

         if ((png_ptr->color_type == PNG_COLOR_TYPE_PALETTE) != 0)
         {
            /* We don't get to here unless there is a tRNS chunk with non-opaque
             * entries - see the checking code at the start of this function.
             */
            png_color back, back_1;
            png_colorp palette = png_ptr->palette;
            int num_palette = png_ptr->num_palette;
            int i;
            if (png_ptr->background_gamma_type == PNG_BACKGROUND_GAMMA_FILE)
            {

               back.red = png_ptr->gamma_table[png_ptr->background.red];
               back.green = png_ptr->gamma_table[png_ptr->background.green];
               back.blue = png_ptr->gamma_table[png_ptr->background.blue];

               back_1.red = png_ptr->gamma_to_1[png_ptr->background.red];
               back_1.green = png_ptr->gamma_to_1[png_ptr->background.green];
               back_1.blue = png_ptr->gamma_to_1[png_ptr->background.blue];
            }
            else
            {
               png_fixed_point g, gs;

               switch (png_ptr->background_gamma_type)
               {
                  case PNG_BACKGROUND_GAMMA_SCREEN:
                     g = (png_ptr->screen_gamma);
                     gs = PNG_FP_1;
                     break;

                  case PNG_BACKGROUND_GAMMA_FILE:
                     g = png_reciprocal(png_ptr->file_gamma);
                     gs = png_reciprocal2(png_ptr->file_gamma,
                         png_ptr->screen_gamma);
                     break;

                  case PNG_BACKGROUND_GAMMA_UNIQUE:
                     g = png_reciprocal(png_ptr->background_gamma);
                     gs = png_reciprocal2(png_ptr->background_gamma,
                         png_ptr->screen_gamma);
                     break;
                  default:
                     g = PNG_FP_1;    /* back_1 */
                     gs = PNG_FP_1;   /* back */
                     break;
               }

               if (png_gamma_significant(gs) != 0)
               {
                  back.red = png_gamma_8bit_correct(png_ptr->background.red,
                      gs);
                  back.green = png_gamma_8bit_correct(png_ptr->background.green,
                      gs);
                  back.blue = png_gamma_8bit_correct(png_ptr->background.blue,
                      gs);
               }

               else
               {
                  back.red   = (png_byte)png_ptr->background.red;
                  back.green = (png_byte)png_ptr->background.green;
                  back.blue  = (png_byte)png_ptr->background.blue;
               }

               if (png_gamma_significant(g) != 0)
               {
                  back_1.red = png_gamma_8bit_correct(png_ptr->background.red,
                      g);
                  back_1.green = png_gamma_8bit_correct(
                      png_ptr->background.green, g);
                  back_1.blue = png_gamma_8bit_correct(png_ptr->background.blue,
                      g);
               }

               else
               {
                  back_1.red   = (png_byte)png_ptr->background.red;
                  back_1.green = (png_byte)png_ptr->background.green;
                  back_1.blue  = (png_byte)png_ptr->background.blue;
               }
            }

            for (i = 0; i < num_palette; i++)
            {
               if (i < (int)png_ptr->num_trans &&
                   png_ptr->trans_alpha[i] != 0xff)
               {
                  if (png_ptr->trans_alpha[i] == 0)
                  {
                     palette[i] = back;
                  }
                  else /* if (png_ptr->trans_alpha[i] != 0xff) */
                  {
                     png_byte v, w;

                     v = png_ptr->gamma_to_1[palette[i].red];
                     png_composite(w, v, png_ptr->trans_alpha[i], back_1.red);
                     palette[i].red = png_ptr->gamma_from_1[w];

                     v = png_ptr->gamma_to_1[palette[i].green];
                     png_composite(w, v, png_ptr->trans_alpha[i], back_1.green);
                     palette[i].green = png_ptr->gamma_from_1[w];

                     v = png_ptr->gamma_to_1[palette[i].blue];
                     png_composite(w, v, png_ptr->trans_alpha[i], back_1.blue);
                     palette[i].blue = png_ptr->gamma_from_1[w];
                  }
               }
               else
- 
               {
                  palette[i].red = png_ptr->gamma_table[palette[i].red];
                  palette[i].green = png_ptr->gamma_table[palette[i].green];
                  palette[i].blue = png_ptr->gamma_table[palette[i].blue];
               }
            }

            /* Prevent the transformations being done again.
             *
             * NOTE: this is highly dubious; it removes the transformations in
             * place.  This seems inconsistent with the general treatment of the
             * transformations elsewhere.
             */
            png_ptr->transformations &= ~(PNG_COMPOSE | PNG_GAMMA);
            png_ptr->flags &= ~PNG_FLAG_OPTIMIZE_ALPHA;
         } /* color_type == PNG_COLOR_TYPE_PALETTE */

         /* if (png_ptr->background_gamma_type!=PNG_BACKGROUND_GAMMA_UNKNOWN) */
         else /* color_type != PNG_COLOR_TYPE_PALETTE */
         {
            int gs_sig, g_sig;
            png_fixed_point g = PNG_FP_1;  /* Correction to linear */
            png_fixed_point gs = PNG_FP_1; /* Correction to screen */

            switch (png_ptr->background_gamma_type)
            {
               case PNG_BACKGROUND_GAMMA_SCREEN:
                  g = png_ptr->screen_gamma;
                  /* gs = PNG_FP_1; */
                  break;

               case PNG_BACKGROUND_GAMMA_FILE:
                  g = png_reciprocal(png_ptr->file_gamma);
                  gs = png_reciprocal2(png_ptr->file_gamma,
                      png_ptr->screen_gamma);
                  break;

               case PNG_BACKGROUND_GAMMA_UNIQUE:
                  g = png_reciprocal(png_ptr->background_gamma);
                  gs = png_reciprocal2(png_ptr->background_gamma,
                      png_ptr->screen_gamma);
                  break;

               default:
                  png_error(png_ptr, "invalid background gamma type");
            }

            g_sig = png_gamma_significant(g);
            gs_sig = png_gamma_significant(gs);

            if (g_sig != 0)
               png_ptr->background_1.gray = png_gamma_correct(png_ptr,
                   png_ptr->background.gray, g);

            if (gs_sig != 0)
               png_ptr->background.gray = png_gamma_correct(png_ptr,
                   png_ptr->background.gray, gs);

            if ((png_ptr->background.red != png_ptr->background.green) ||
                (png_ptr->background.red != png_ptr->background.blue) ||
                (png_ptr->background.red != png_ptr->background.gray))
            {
               /* RGB or RGBA with color background */
               if (g_sig != 0)
               {
                  png_ptr->background_1.red = png_gamma_correct(png_ptr,
                      png_ptr->background.red, g);

                  png_ptr->background_1.green = png_gamma_correct(png_ptr,
                      png_ptr->background.green, g);

                  png_ptr->background_1.blue = png_gamma_correct(png_ptr,
                      png_ptr->background.blue, g);
               }

               if (gs_sig != 0)
               {
                  png_ptr->background.red = png_gamma_correct(png_ptr,
                      png_ptr->background.red, gs);

                  png_ptr->background.green = png_gamma_correct(png_ptr,
                      png_ptr->background.green, gs);

                  png_ptr->background.blue = png_gamma_correct(png_ptr,
                      png_ptr->background.blue, gs);
               }
            }

            else
            {
               /* GRAY, GRAY ALPHA, RGB, or RGBA with gray background */
               png_ptr->background_1.red = png_ptr->background_1.green
                   = png_ptr->background_1.blue = png_ptr->background_1.gray;

               png_ptr->background.red = png_ptr->background.green
                   = png_ptr->background.blue = png_ptr->background.gray;
            }

            /* The background is now in screen gamma: */
            png_ptr->background_gamma_type = PNG_BACKGROUND_GAMMA_SCREEN;
         } /* color_type != PNG_COLOR_TYPE_PALETTE */
      }/* png_ptr->transformations & PNG_BACKGROUND */

      else
      /* Transformation does not include PNG_BACKGROUND */
#endif /* READ_BACKGROUND */
      if (png_ptr->color_type == PNG_COLOR_TYPE_PALETTE
#ifdef PNG_READ_RGB_TO_GRAY_SUPPORTED
         /* RGB_TO_GRAY needs to have non-gamma-corrected values! */
         && ((png_ptr->transformations & PNG_EXPAND) == 0 ||
         (png_ptr->transformations & PNG_RGB_TO_GRAY) == 0)
#endif
         )
      {
         png_colorp palette = png_ptr->palette;
         int num_palette = png_ptr->num_palette;
         int i;

         /* NOTE: there are other transformations that should probably be in
          * here too.
          */
         for (i = 0; i < num_palette; i++)
         {
            palette[i].red = png_ptr->gamma_table[palette[i].red];
            palette[i].green = png_ptr->gamma_table[palette[i].green];
            palette[i].blue = png_ptr->gamma_table[palette[i].blue];
         }

         /* Done the gamma correction. */
         png_ptr->transformations &= ~PNG_GAMMA;
      } /* color_type == PALETTE && !PNG_BACKGROUND transformation */
   }
#ifdef PNG_READ_BACKGROUND_SUPPORTED
   else
#endif
#endif /* READ_GAMMA */

#ifdef PNG_READ_BACKGROUND_SUPPORTED
   /* No GAMMA transformation (see the hanging else 4 lines above) */
   if ((png_ptr->transformations & PNG_COMPOSE) != 0 &&
       (png_ptr->color_type == PNG_COLOR_TYPE_PALETTE))
   {
      int i;
      int istop = (int)png_ptr->num_trans;
      png_color back;
      png_colorp palette = png_ptr->palette;

      back.red   = (png_byte)png_ptr->background.red;
      back.green = (png_byte)png_ptr->background.green;
      back.blue  = (png_byte)png_ptr->background.blue;

      for (i = 0; i < istop; i++)
      {
         if (png_ptr->trans_alpha[i] == 0)
         {
            palette[i] = back;
         }

         else if (png_ptr->trans_alpha[i] != 0xff)
         {
            /* The png_composite() macro is defined in png.h */
            png_composite(palette[i].red, palette[i].red,
                png_ptr->trans_alpha[i], back.red);

            png_composite(palette[i].green, palette[i].green,
                png_ptr->trans_alpha[i], back.green);

            png_composite(palette[i].blue, palette[i].blue,
                png_ptr->trans_alpha[i], back.blue);
         }
      }

      png_ptr->transformations &= ~PNG_COMPOSE;
   }
#endif /* READ_BACKGROUND */

#ifdef PNG_READ_SHIFT_SUPPORTED
   if ((png_ptr->transformations & PNG_SHIFT) != 0 &&
       (png_ptr->transformations & PNG_EXPAND) == 0 &&
       (png_ptr->color_type == PNG_COLOR_TYPE_PALETTE))
   {
      int i;
      int istop = png_ptr->num_palette;
      int shift = 8 - png_ptr->sig_bit.red;

      png_ptr->transformations &= ~PNG_SHIFT;

      /* significant bits can be in the range 1 to 7 for a meaningful result, if
       * the number of significant bits is 0 then no shift is done (this is an
       * error condition which is silently ignored.)
       */
      if (shift > 0 && shift < 8)
         for (i=0; i<istop; ++i)
         {
            int component = png_ptr->palette[i].red;

            component >>= shift;
            png_ptr->palette[i].red = (png_byte)component;
         }

      shift = 8 - png_ptr->sig_bit.green;
      if (shift > 0 && shift < 8)
         for (i=0; i<istop; ++i)
         {
            int component = png_ptr->palette[i].green;

            component >>= shift;
            png_ptr->palette[i].green = (png_byte)component;
         }

      shift = 8 - png_ptr->sig_bit.blue;
      if (shift > 0 && shift < 8)
         for (i=0; i<istop; ++i)
         {
            int component = png_ptr->palette[i].blue;

            component >>= shift;
            png_ptr->palette[i].blue = (png_byte)component;
         }
   }
#endif /* READ_SHIFT */
}
```


#### 修复函数（修复后）

```c
void /* PRIVATE */
png_init_read_transformations(png_structrp png_ptr)
{
   png_debug(1, "in png_init_read_transformations");

   /* This internal function is called from png_read_start_row in pngrutil.c
    * and it is called before the 'rowbytes' calculation is done, so the code
    * in here can change or update the transformations flags.
    *
    * First do updates that do not depend on the details of the PNG image data
    * being processed.
    */

#ifdef PNG_READ_GAMMA_SUPPORTED
   /* Prior to 1.5.4 these tests were performed from png_set_gamma, 1.5.4 adds
    * png_set_alpha_mode and this is another source for a default file gamma so
    * the test needs to be performed later - here.  In addition prior to 1.5.4
    * the tests were repeated for the PALETTE color type here - this is no
    * longer necessary (and doesn't seem to have been necessary before.)
    *
    * PNGv3: the new mandatory precedence/priority rules for colour space chunks
    * are handled here (by calling the above function).
    *
    * Turn the gamma transformation on or off as appropriate.  Notice that
    * PNG_GAMMA just refers to the file->screen correction.  Alpha composition
    * may independently cause gamma correction because it needs linear data
    * (e.g. if the file has a gAMA chunk but the screen gamma hasn't been
    * specified.)  In any case this flag may get turned off in the code
    * immediately below if the transform can be handled outside the row loop.
    */
   if (png_init_gamma_values(png_ptr) != 0)
      png_ptr->transformations |= PNG_GAMMA;

   else
      png_ptr->transformations &= ~PNG_GAMMA;
#endif

   /* Certain transformations have the effect of preventing other
    * transformations that happen afterward in png_do_read_transformations;
    * resolve the interdependencies here.  From the code of
    * png_do_read_transformations the order is:
    *
    *  1) PNG_EXPAND (including PNG_EXPAND_tRNS)
    *  2) PNG_STRIP_ALPHA (if no compose)
    *  3) PNG_RGB_TO_GRAY
    *  4) PNG_GRAY_TO_RGB iff !PNG_BACKGROUND_IS_GRAY
    *  5) PNG_COMPOSE
    *  6) PNG_GAMMA
    *  7) PNG_STRIP_ALPHA (if compose)
    *  8) PNG_ENCODE_ALPHA
    *  9) PNG_SCALE_16_TO_8
    * 10) PNG_16_TO_8
    * 11) PNG_QUANTIZE (converts to palette)
    * 12) PNG_EXPAND_16
    * 13) PNG_GRAY_TO_RGB iff PNG_BACKGROUND_IS_GRAY
    * 14) PNG_INVERT_MONO
    * 15) PNG_INVERT_ALPHA
    * 16) PNG_SHIFT
    * 17) PNG_PACK
    * 18) PNG_BGR
    * 19) PNG_PACKSWAP
    * 20) PNG_FILLER (includes PNG_ADD_ALPHA)
    * 21) PNG_SWAP_ALPHA
    * 22) PNG_SWAP_BYTES
    * 23) PNG_USER_TRANSFORM [must be last]
    */
#ifdef PNG_READ_STRIP_ALPHA_SUPPORTED
   if ((png_ptr->transformations & PNG_STRIP_ALPHA) != 0 &&
       (png_ptr->transformations & PNG_COMPOSE) == 0)
   {
      /* Stripping the alpha channel happens immediately after the 'expand'
       * transformations, before all other transformation, so it cancels out
       * the alpha handling.  It has the side effect negating the effect of
       * PNG_EXPAND_tRNS too:
       */
      png_ptr->transformations &= ~(PNG_BACKGROUND_EXPAND | PNG_ENCODE_ALPHA |
         PNG_EXPAND_tRNS);
      png_ptr->flags &= ~PNG_FLAG_OPTIMIZE_ALPHA;

      /* Kill the tRNS chunk itself too.  Prior to 1.5.4 this did not happen
       * so transparency information would remain just so long as it wasn't
       * expanded.  This produces unexpected API changes if the set of things
       * that do PNG_EXPAND_tRNS changes (perfectly possible given the
       * documentation - which says ask for what you want, accept what you
       * get.)  This makes the behavior consistent from 1.5.4:
       */
      png_ptr->num_trans = 0;
   }
#endif /* STRIP_ALPHA supported, no COMPOSE */

#ifdef PNG_READ_ALPHA_MODE_SUPPORTED
   /* If the screen gamma is about 1.0 then the OPTIMIZE_ALPHA and ENCODE_ALPHA
    * settings will have no effect.
    */
   if (png_gamma_significant(png_ptr->screen_gamma) == 0)
   {
      png_ptr->transformations &= ~PNG_ENCODE_ALPHA;
      png_ptr->flags &= ~PNG_FLAG_OPTIMIZE_ALPHA;
   }
#endif

#ifdef PNG_READ_RGB_TO_GRAY_SUPPORTED
   /* Make sure the coefficients for the rgb to gray conversion are set
    * appropriately.
    */
   if ((png_ptr->transformations & PNG_RGB_TO_GRAY) != 0)
      png_set_rgb_coefficients(png_ptr);
#endif

#ifdef PNG_READ_GRAY_TO_RGB_SUPPORTED
#if defined(PNG_READ_EXPAND_SUPPORTED) && defined(PNG_READ_BACKGROUND_SUPPORTED)
   /* Detect gray background and attempt to enable optimization for
    * gray --> RGB case.
    *
    * Note:  if PNG_BACKGROUND_EXPAND is set and color_type is either RGB or
    * RGB_ALPHA (in which case need_expand is superfluous anyway), the
    * background color might actually be gray yet not be flagged as such.
    * This is not a problem for the current code, which uses
    * PNG_BACKGROUND_IS_GRAY only to decide when to do the
    * png_do_gray_to_rgb() transformation.
    *
    * TODO: this code needs to be revised to avoid the complexity and
    * interdependencies.  The color type of the background should be recorded in
    * png_set_background, along with the bit depth, then the code has a record
    * of exactly what color space the background is currently in.
    */
   if ((png_ptr->transformations & PNG_BACKGROUND_EXPAND) != 0)
   {
      /* PNG_BACKGROUND_EXPAND: the background is in the file color space, so if
       * the file was grayscale the background value is gray.
       */
      if ((png_ptr->color_type & PNG_COLOR_MASK_COLOR) == 0)
         png_ptr->mode |= PNG_BACKGROUND_IS_GRAY;
   }

   else if ((png_ptr->transformations & PNG_COMPOSE) != 0)
   {
      /* PNG_COMPOSE: png_set_background was called with need_expand false,
       * so the color is in the color space of the output or png_set_alpha_mode
       * was called and the color is black.  Ignore RGB_TO_GRAY because that
       * happens before GRAY_TO_RGB.
       */
      if ((png_ptr->transformations & PNG_GRAY_TO_RGB) != 0)
      {
         if (png_ptr->background.red == png_ptr->background.green &&
             png_ptr->background.red == png_ptr->background.blue)
         {
            png_ptr->mode |= PNG_BACKGROUND_IS_GRAY;
            png_ptr->background.gray = png_ptr->background.red;
         }
      }
   }
#endif /* READ_EXPAND && READ_BACKGROUND */
#endif /* READ_GRAY_TO_RGB */

   /* For indexed PNG data (PNG_COLOR_TYPE_PALETTE) many of the transformations
    * can be performed directly on the palette, and some (such as rgb to gray)
    * can be optimized inside the palette.  This is particularly true of the
    * composite (background and alpha) stuff, which can be pretty much all done
    * in the palette even if the result is expanded to RGB or gray afterward.
    *
    * NOTE: this is Not Yet Implemented, the code behaves as in 1.5.1 and
    * earlier and the palette stuff is actually handled on the first row.  This
    * leads to the reported bug that the palette returned by png_get_PLTE is not
    * updated.
    */
   if (png_ptr->color_type == PNG_COLOR_TYPE_PALETTE)
      png_init_palette_transformations(png_ptr);

   else
      png_init_rgb_transformations(png_ptr);

#if defined(PNG_READ_BACKGROUND_SUPPORTED) && \
   defined(PNG_READ_EXPAND_16_SUPPORTED)
   if ((png_ptr->transformations & PNG_EXPAND_16) != 0 &&
       (png_ptr->transformations & PNG_COMPOSE) != 0 &&
       (png_ptr->transformations & PNG_BACKGROUND_EXPAND) == 0 &&
       png_ptr->bit_depth != 16)
   {
      /* TODO: fix this.  Because the expand_16 operation is after the compose
       * handling the background color must be 8, not 16, bits deep, but the
       * application will supply a 16-bit value so reduce it here.
       *
       * The PNG_BACKGROUND_EXPAND code above does not expand to 16 bits at
       * present, so that case is ok (until do_expand_16 is moved.)
       *
       * NOTE: this discards the low 16 bits of the user supplied background
       * color, but until expand_16 works properly there is no choice!
       */
#     define CHOP(x) (x)=((png_uint_16)PNG_DIV257(x))
      CHOP(png_ptr->background.red);
      CHOP(png_ptr->background.green);
      CHOP(png_ptr->background.blue);
      CHOP(png_ptr->background.gray);
#     undef CHOP
   }
#endif /* READ_BACKGROUND && READ_EXPAND_16 */

#if defined(PNG_READ_BACKGROUND_SUPPORTED) && \
   (defined(PNG_READ_SCALE_16_TO_8_SUPPORTED) || \
   defined(PNG_READ_STRIP_16_TO_8_SUPPORTED))
   if ((png_ptr->transformations & (PNG_16_TO_8|PNG_SCALE_16_TO_8)) != 0 &&
       (png_ptr->transformations & PNG_COMPOSE) != 0 &&
       (png_ptr->transformations & PNG_BACKGROUND_EXPAND) == 0 &&
       png_ptr->bit_depth == 16)
   {
      /* On the other hand, if a 16-bit file is to be reduced to 8-bits per
       * component this will also happen after PNG_COMPOSE and so the background
       * color must be pre-expanded here.
       *
       * TODO: fix this too.
       */
      png_ptr->background.red = (png_uint_16)(png_ptr->background.red * 257);
      png_ptr->background.green =
         (png_uint_16)(png_ptr->background.green * 257);
      png_ptr->background.blue = (png_uint_16)(png_ptr->background.blue * 257);
      png_ptr->background.gray = (png_uint_16)(png_ptr->background.gray * 257);
   }
#endif

   /* NOTE: below 'PNG_READ_ALPHA_MODE_SUPPORTED' is presumed to also enable the
    * background support (see the comments in scripts/pnglibconf.dfa), this
    * allows pre-multiplication of the alpha channel to be implemented as
    * compositing on black.  This is probably sub-optimal and has been done in
    * 1.5.4 betas simply to enable external critique and testing (i.e. to
    * implement the new API quickly, without lots of internal changes.)
    */

#ifdef PNG_READ_GAMMA_SUPPORTED
#  ifdef PNG_READ_BACKGROUND_SUPPORTED
      /* Includes ALPHA_MODE */
      png_ptr->background_1 = png_ptr->background;
#  endif

   /* This needs to change - in the palette image case a whole set of tables are
    * built when it would be quicker to just calculate the correct value for
    * each palette entry directly.  Also, the test is too tricky - why check
    * PNG_RGB_TO_GRAY if PNG_GAMMA is not set?  The answer seems to be that
    * PNG_GAMMA is cancelled even if the gamma is known?  The test excludes the
    * PNG_COMPOSE case, so apparently if there is no *overall* gamma correction
    * the gamma tables will not be built even if composition is required on a
    * gamma encoded value.
    *
    * In 1.5.4 this is addressed below by an additional check on the individual
    * file gamma - if it is not 1.0 both RGB_TO_GRAY and COMPOSE need the
    * tables.
    */
   if ((png_ptr->transformations & PNG_GAMMA) != 0 ||
       ((png_ptr->transformations & PNG_RGB_TO_GRAY) != 0 &&
        (png_gamma_significant(png_ptr->file_gamma) != 0 ||
         png_gamma_significant(png_ptr->screen_gamma) != 0)) ||
        ((png_ptr->transformations & PNG_COMPOSE) != 0 &&
         (png_gamma_significant(png_ptr->file_gamma) != 0 ||
          png_gamma_significant(png_ptr->screen_gamma) != 0
#  ifdef PNG_READ_BACKGROUND_SUPPORTED
         || (png_ptr->background_gamma_type == PNG_BACKGROUND_GAMMA_UNIQUE &&
           png_gamma_significant(png_ptr->background_gamma) != 0)
#  endif
        )) || ((png_ptr->transformations & PNG_ENCODE_ALPHA) != 0 &&
       png_gamma_significant(png_ptr->screen_gamma) != 0))
   {
      png_build_gamma_table(png_ptr, png_ptr->bit_depth);

#ifdef PNG_READ_BACKGROUND_SUPPORTED
      if ((png_ptr->transformations & PNG_COMPOSE) != 0)
      {
         /* Issue a warning about this combination: because RGB_TO_GRAY is
          * optimized to do the gamma transform if present yet do_background has
          * to do the same thing if both options are set a
          * double-gamma-correction happens.  This is true in all versions of
          * libpng to date.
          */
         if ((png_ptr->transformations & PNG_RGB_TO_GRAY) != 0)
            png_warning(png_ptr,
                "libpng does not support gamma+background+rgb_to_gray");

         if ((png_ptr->color_type == PNG_COLOR_TYPE_PALETTE) != 0)
         {
            /* We don't get to here unless there is a tRNS chunk with non-opaque
             * entries - see the checking code at the start of this function.
             */
            png_color back, back_1;
            png_colorp palette = png_ptr->palette;
            int num_palette = png_ptr->num_palette;
            int i;
            if (png_ptr->background_gamma_type == PNG_BACKGROUND_GAMMA_FILE)
            {

               back.red = png_ptr->gamma_table[png_ptr->background.red];
               back.green = png_ptr->gamma_table[png_ptr->background.green];
               back.blue = png_ptr->gamma_table[png_ptr->background.blue];

               back_1.red = png_ptr->gamma_to_1[png_ptr->background.red];
               back_1.green = png_ptr->gamma_to_1[png_ptr->background.green];
               back_1.blue = png_ptr->gamma_to_1[png_ptr->background.blue];
            }
            else
            {
               png_fixed_point g, gs;

               switch (png_ptr->background_gamma_type)
               {
                  case PNG_BACKGROUND_GAMMA_SCREEN:
                     g = (png_ptr->screen_gamma);
                     gs = PNG_FP_1;
                     break;

                  case PNG_BACKGROUND_GAMMA_FILE:
                     g = png_reciprocal(png_ptr->file_gamma);
                     gs = png_reciprocal2(png_ptr->file_gamma,
                         png_ptr->screen_gamma);
                     break;

                  case PNG_BACKGROUND_GAMMA_UNIQUE:
                     g = png_reciprocal(png_ptr->background_gamma);
                     gs = png_reciprocal2(png_ptr->background_gamma,
                         png_ptr->screen_gamma);
                     break;
                  default:
                     g = PNG_FP_1;    /* back_1 */
                     gs = PNG_FP_1;   /* back */
                     break;
               }

               if (png_gamma_significant(gs) != 0)
               {
                  back.red = png_gamma_8bit_correct(png_ptr->background.red,
                      gs);
                  back.green = png_gamma_8bit_correct(png_ptr->background.green,
                      gs);
                  back.blue = png_gamma_8bit_correct(png_ptr->background.blue,
                      gs);
               }

               else
               {
                  back.red   = (png_byte)png_ptr->background.red;
                  back.green = (png_byte)png_ptr->background.green;
                  back.blue  = (png_byte)png_ptr->background.blue;
               }

               if (png_gamma_significant(g) != 0)
               {
                  back_1.red = png_gamma_8bit_correct(png_ptr->background.red,
                      g);
                  back_1.green = png_gamma_8bit_correct(
                      png_ptr->background.green, g);
                  back_1.blue = png_gamma_8bit_correct(png_ptr->background.blue,
                      g);
               }

               else
               {
                  back_1.red   = (png_byte)png_ptr->background.red;
                  back_1.green = (png_byte)png_ptr->background.green;
                  back_1.blue  = (png_byte)png_ptr->background.blue;
               }
            }

            for (i = 0; i < num_palette; i++)
            {
               if (i < (int)png_ptr->num_trans &&
                   png_ptr->trans_alpha[i] != 0xff)
               {
                  if (png_ptr->trans_alpha[i] == 0)
                  {
                     palette[i] = back;
                  }
                  else /* if (png_ptr->trans_alpha[i] != 0xff) */
                  {
                     if ((png_ptr->flags & PNG_FLAG_OPTIMIZE_ALPHA) != 0)
                     {
                        /* Premultiply only:
                         * component = round((component * alpha) / 255)
                         */
                        png_uint_32 component;

                        component = png_ptr->gamma_to_1[palette[i].red];
                        component =
                            (component * png_ptr->trans_alpha[i] + 128) / 255;
                        palette[i].red = png_ptr->gamma_from_1[component];

                        component = png_ptr->gamma_to_1[palette[i].green];
                        component =
                            (component * png_ptr->trans_alpha[i] + 128) / 255;
                        palette[i].green = png_ptr->gamma_from_1[component];

                        component = png_ptr->gamma_to_1[palette[i].blue];
                        component =
                            (component * png_ptr->trans_alpha[i] + 128) / 255;
                        palette[i].blue = png_ptr->gamma_from_1[component];
                     }
                     else
                     {
                        /* Composite with background color:
                         * component =
                         *    alpha * component + (1 - alpha) * background
                         */
                        png_byte v, w;

                        v = png_ptr->gamma_to_1[palette[i].red];
                        png_composite(w, v,
                            png_ptr->trans_alpha[i], back_1.red);
                        palette[i].red = png_ptr->gamma_from_1[w];

                        v = png_ptr->gamma_to_1[palette[i].green];
                        png_composite(w, v,
                            png_ptr->trans_alpha[i], back_1.green);
                        palette[i].green = png_ptr->gamma_from_1[w];

                        v = png_ptr->gamma_to_1[palette[i].blue];
                        png_composite(w, v,
                            png_ptr->trans_alpha[i], back_1.blue);
                        palette[i].blue = png_ptr->gamma_from_1[w];
                     }
                  }
               }
               else
               {
                  palette[i].red = png_ptr->gamma_table[palette[i].red];
                  palette[i].green = png_ptr->gamma_table[palette[i].green];
                  palette[i].blue = png_ptr->gamma_table[palette[i].blue];
               }
            }

            /* Prevent the transformations being done again.
             *
             * NOTE: this is highly dubious; it removes the transformations in
             * place.  This seems inconsistent with the general treatment of the
             * transformations elsewhere.
             */
            png_ptr->transformations &= ~(PNG_COMPOSE | PNG_GAMMA);
            png_ptr->flags &= ~PNG_FLAG_OPTIMIZE_ALPHA;
         } /* color_type == PNG_COLOR_TYPE_PALETTE */

         /* if (png_ptr->background_gamma_type!=PNG_BACKGROUND_GAMMA_UNKNOWN) */
         else /* color_type != PNG_COLOR_TYPE_PALETTE */
         {
            int gs_sig, g_sig;
            png_fixed_point g = PNG_FP_1;  /* Correction to linear */
            png_fixed_point gs = PNG_FP_1; /* Correction to screen */

            switch (png_ptr->background_gamma_type)
            {
               case PNG_BACKGROUND_GAMMA_SCREEN:
                  g = png_ptr->screen_gamma;
                  /* gs = PNG_FP_1; */
                  break;

               case PNG_BACKGROUND_GAMMA_FILE:
                  g = png_reciprocal(png_ptr->file_gamma);
                  gs = png_reciprocal2(png_ptr->file_gamma,
                      png_ptr->screen_gamma);
                  break;

               case PNG_BACKGROUND_GAMMA_UNIQUE:
                  g = png_reciprocal(png_ptr->background_gamma);
                  gs = png_reciprocal2(png_ptr->background_gamma,
                      png_ptr->screen_gamma);
                  break;

               default:
                  png_error(png_ptr, "invalid background gamma type");
            }

            g_sig = png_gamma_significant(g);
            gs_sig = png_gamma_significant(gs);

            if (g_sig != 0)
               png_ptr->background_1.gray = png_gamma_correct(png_ptr,
                   png_ptr->background.gray, g);

            if (gs_sig != 0)
               png_ptr->background.gray = png_gamma_correct(png_ptr,
                   png_ptr->background.gray, gs);

            if ((png_ptr->background.red != png_ptr->background.green) ||
                (png_ptr->background.red != png_ptr->background.blue) ||
                (png_ptr->background.red != png_ptr->background.gray))
            {
               /* RGB or RGBA with color background */
               if (g_sig != 0)
               {
                  png_ptr->background_1.red = png_gamma_correct(png_ptr,
                      png_ptr->background.red, g);

                  png_ptr->background_1.green = png_gamma_correct(png_ptr,
                      png_ptr->background.green, g);

                  png_ptr->background_1.blue = png_gamma_correct(png_ptr,
                      png_ptr->background.blue, g);
               }

               if (gs_sig != 0)
               {
                  png_ptr->background.red = png_gamma_correct(png_ptr,
                      png_ptr->background.red, gs);

                  png_ptr->background.green = png_gamma_correct(png_ptr,
                      png_ptr->background.green, gs);

                  png_ptr->background.blue = png_gamma_correct(png_ptr,
                      png_ptr->background.blue, gs);
               }
            }

            else
            {
               /* GRAY, GRAY ALPHA, RGB, or RGBA with gray background */
               png_ptr->background_1.red = png_ptr->background_1.green
                   = png_ptr->background_1.blue = png_ptr->background_1.gray;

               png_ptr->background.red = png_ptr->background.green
                   = png_ptr->background.blue = png_ptr->background.gray;
            }

            /* The background is now in screen gamma: */
            png_ptr->background_gamma_type = PNG_BACKGROUND_GAMMA_SCREEN;
         } /* color_type != PNG_COLOR_TYPE_PALETTE */
      }/* png_ptr->transformations & PNG_BACKGROUND */

      else
      /* Transformation does not include PNG_BACKGROUND */
#endif /* READ_BACKGROUND */
      if (png_ptr->color_type == PNG_COLOR_TYPE_PALETTE
#ifdef PNG_READ_RGB_TO_GRAY_SUPPORTED
         /* RGB_TO_GRAY needs to have non-gamma-corrected values! */
         && ((png_ptr->transformations & PNG_EXPAND) == 0 ||
         (png_ptr->transformations & PNG_RGB_TO_GRAY) == 0)
#endif
         )
      {
         png_colorp palette = png_ptr->palette;
         int num_palette = png_ptr->num_palette;
         int i;

         /* NOTE: there are other transformations that should probably be in
          * here too.
          */
         for (i = 0; i < num_palette; i++)
         {
            palette[i].red = png_ptr->gamma_table[palette[i].red];
            palette[i].green = png_ptr->gamma_table[palette[i].green];
            palette[i].blue = png_ptr->gamma_table[palette[i].blue];
         }

         /* Done the gamma correction. */
         png_ptr->transformations &= ~PNG_GAMMA;
      } /* color_type == PALETTE && !PNG_BACKGROUND transformation */
   }
#ifdef PNG_READ_BACKGROUND_SUPPORTED
   else
#endif
#endif /* READ_GAMMA */

#ifdef PNG_READ_BACKGROUND_SUPPORTED
   /* No GAMMA transformation (see the hanging else 4 lines above) */
   if ((png_ptr->transformations & PNG_COMPOSE) != 0 &&
       (png_ptr->color_type == PNG_COLOR_TYPE_PALETTE))
   {
      int i;
      int istop = (int)png_ptr->num_trans;
      png_color back;
      png_colorp palette = png_ptr->palette;

      back.red   = (png_byte)png_ptr->background.red;
      back.green = (png_byte)png_ptr->background.green;
      back.blue  = (png_byte)png_ptr->background.blue;

      for (i = 0; i < istop; i++)
      {
         if (png_ptr->trans_alpha[i] == 0)
         {
            palette[i] = back;
         }

         else if (png_ptr->trans_alpha[i] != 0xff)
         {
            /* The png_composite() macro is defined in png.h */
            png_composite(palette[i].red, palette[i].red,
                png_ptr->trans_alpha[i], back.red);

            png_composite(palette[i].green, palette[i].green,
                png_ptr->trans_alpha[i], back.green);

            png_composite(palette[i].blue, palette[i].blue,
                png_ptr->trans_alpha[i], back.blue);
         }
      }

      png_ptr->transformations &= ~PNG_COMPOSE;
   }
#endif /* READ_BACKGROUND */

#ifdef PNG_READ_SHIFT_SUPPORTED
   if ((png_ptr->transformations & PNG_SHIFT) != 0 &&
       (png_ptr->transformations & PNG_EXPAND) == 0 &&
       (png_ptr->color_type == PNG_COLOR_TYPE_PALETTE))
   {
      int i;
      int istop = png_ptr->num_palette;
      int shift = 8 - png_ptr->sig_bit.red;

      png_ptr->transformations &= ~PNG_SHIFT;

      /* significant bits can be in the range 1 to 7 for a meaningful result, if
       * the number of significant bits is 0 then no shift is done (this is an
       * error condition which is silently ignored.)
       */
      if (shift > 0 && shift < 8)
         for (i=0; i<istop; ++i)
         {
            int component = png_ptr->palette[i].red;

            component >>= shift;
            png_ptr->palette[i].red = (png_byte)component;
         }

      shift = 8 - png_ptr->sig_bit.green;
      if (shift > 0 && shift < 8)
         for (i=0; i<istop; ++i)
         {
            int component = png_ptr->palette[i].green;

            component >>= shift;
            png_ptr->palette[i].green = (png_byte)component;
         }

      shift = 8 - png_ptr->sig_bit.blue;
      if (shift > 0 && shift < 8)
         for (i=0; i<istop; ++i)
         {
            int component = png_ptr->palette[i].blue;

            component >>= shift;
            png_ptr->palette[i].blue = (png_byte)component;
         }
   }
#endif /* READ_SHIFT */
}
```


#### 关键变更行

```diff
-                      png_byte v, w;
- 
-                      v = png_ptr->gamma_to_1[palette[i].red];
-                      png_composite(w, v, png_ptr->trans_alpha[i], back_1.red);
-                      palette[i].red = png_ptr->gamma_from_1[w];
- 
-                      v = png_ptr->gamma_to_1[palette[i].green];
-                      png_composite(w, v, png_ptr->trans_alpha[i], back_1.green);
-                      palette[i].green = png_ptr->gamma_from_1[w];
- 
-                      v = png_ptr->gamma_to_1[palette[i].blue];
-                      png_composite(w, v, png_ptr->trans_alpha[i], back_1.blue);
-                      palette[i].blue = png_ptr->gamma_from_1[w];
- - 
+                      if ((png_ptr->flags & PNG_FLAG_OPTIMIZE_ALPHA) != 0)
+                      {
+                         /* Premultiply only:
+                          * component = round((component * alpha) / 255)
+                          */
+                         png_uint_32 component;
+ 
+                         component = png_ptr->gamma_to_1[palette[i].red];
+                         component =
+                             (component * png_ptr->trans_alpha[i] + 128) / 255;
+                         palette[i].red = png_ptr->gamma_from_1[component];
+ 
+                         component = png_ptr->gamma_to_1[palette[i].green];
+                         component =
+                             (component * png_ptr->trans_alpha[i] + 128) / 255;
+                         palette[i].green = png_ptr->gamma_from_1[component];
+ 
+                         component = png_ptr->gamma_to_1[palette[i].blue];
+                         component =
+                             (component * png_ptr->trans_alpha[i] + 128) / 255;
+                         palette[i].blue = png_ptr->gamma_from_1[component];
+                      }
+                      else
+                      {
+                         /* Composite with background color:
+                          * component =
+                          *    alpha * component + (1 - alpha) * background
+                          */
+                         png_byte v, w;
+ 
+                         v = png_ptr->gamma_to_1[palette[i].red];
+                         png_composite(w, v,
+                             png_ptr->trans_alpha[i], back_1.red);
+                         palette[i].red = png_ptr->gamma_from_1[w];
+ 
+                         v = png_ptr->gamma_to_1[palette[i].green];
+                         png_composite(w, v,
+                             png_ptr->trans_alpha[i], back_1.green);
+                         palette[i].green = png_ptr->gamma_from_1[w];
+ 
+                         v = png_ptr->gamma_to_1[palette[i].blue];
+                         png_composite(w, v,
+                             png_ptr->trans_alpha[i], back_1.blue);
+                         palette[i].blue = png_ptr->gamma_from_1[w];
+                      }
```


---

<a id="cve202564720"></a>

## CVE-2025-64720  ·  third_party_libpng  ·  无

**参考链接**：<https://gitcode.com/openharmony/third_party_libpng/pull/84>

**漏洞描述**：_（未获取到描述，可能需要 GITCODE_PRIVATE_TOKEN 或 GITHUB_TOKEN）_


共涉及 **6** 个函数／代码区域：

### 1. `（无函数名）`

**文件**：`CVE-2025-64505.patch`  |  **变更**：+158 / -0 行  |  ⚠️ 仅 diff 上下文（源文件不可用，代码不完整）

**Hunk 位置**：`@@ -0,0 +1,158 @@`


#### 代码变更（diff 上下文，源文件不可用）

```diff
+ diff --git a/pngrtran.c b/pngrtran.c
+ index 1526123..072db9a 100644
+ --- a/pngrtran.c
+ +++ b/pngrtran.c
+ @@ -439,9 +439,19 @@ png_set_quantize(png_structrp png_ptr, png_colorp palette,
+     {
+        int i;
+  
+ +      /* Initialize the array to index colors.
+ +       *
+ +       * Ensure quantize_index can fit 256 elements (PNG_MAX_PALETTE_LENGTH)
+ +       * rather than num_palette elements. This is to prevent buffer overflows
+ +       * caused by malformed PNG files with out-of-range palette indices.
+ +       *
+ +       * Be careful to avoid leaking memory. Applications are allowed to call
+ +       * this function more than once per png_struct.
+ +       */
+ +      png_free(png_ptr, png_ptr->quantize_index);
+        png_ptr->quantize_index = (png_bytep)png_malloc(png_ptr,
+ -          (png_alloc_size_t)num_palette);
+ -      for (i = 0; i < num_palette; i++)
+ +          PNG_MAX_PALETTE_LENGTH);
+ +      for (i = 0; i < PNG_MAX_PALETTE_LENGTH; i++)
+           png_ptr->quantize_index[i] = (png_byte)i;
+     }
+  
+ @@ -453,15 +463,15 @@ png_set_quantize(png_structrp png_ptr, png_colorp palette,
+            * Perhaps not the best solution, but good enough.
+            */
+  
+ -         int i;
+ +         png_bytep quantize_sort;
+ +         int i, j;
+  
+ -         /* Initialize an array to sort colors */
+ -         png_ptr->quantize_sort = (png_bytep)png_malloc(png_ptr,
+ +         /* Initialize the local array to sort colors. */
+ +         quantize_sort = (png_bytep)png_malloc(png_ptr,
+               (png_alloc_size_t)num_palette);
+  
+ -         /* Initialize the quantize_sort array */
+           for (i = 0; i < num_palette; i++)
+ -            png_ptr->quantize_sort[i] = (png_byte)i;
+ +            quantize_sort[i] = (png_byte)i;
+  
+           /* Find the least used palette entries by starting a
+            * bubble sort, and running it until we have sorted
+ @@ -473,19 +483,18 @@ png_set_quantize(png_structrp png_ptr, png_colorp palette,
+           for (i = num_palette - 1; i >= maximum_colors; i--)
+           {
+              int done; /* To stop early if the list is pre-sorted */
+ -            int j;
+  
+              done = 1;
+              for (j = 0; j < i; j++)
+              {
+ -               if (histogram[png_ptr->quantize_sort[j]]
+ -                   < histogram[png_ptr->quantize_sort[j + 1]])
+ +               if (histogram[quantize_sort[j]]
+ +                   < histogram[quantize_sort[j + 1]])
+                 {
+                    png_byte t;
+  
+ -                  t = png_ptr->quantize_sort[j];
+ -                  png_ptr->quantize_sort[j] = png_ptr->quantize_sort[j + 1];
+ -                  png_ptr->quantize_sort[j + 1] = t;
+ +                  t = quantize_sort[j];
+ +                  quantize_sort[j] = quantize_sort[j + 1];
+ +                  quantize_sort[j + 1] = t;
+                    done = 0;
+                 }
+              }
+ @@ -497,18 +506,18 @@ png_set_quantize(png_structrp png_ptr, png_colorp palette,
+           /* Swap the palette around, and set up a table, if necessary */
+           if (full_quantize != 0)
+           {
+ -            int j = num_palette;
+ +            j = num_palette;
+  
+              /* Put all the useful colors within the max, but don't
+               * move the others.
+               */
+              for (i = 0; i < maximum_colors; i++)
+              {
+ -               if ((int)png_ptr->quantize_sort[i] >= maximum_colors)
+ +               if ((int)quantize_sort[i] >= maximum_colors)
+                 {
+                    do
+                       j--;
+ -                  while ((int)png_ptr->quantize_sort[j] >= maximum_colors);
+ +                  while ((int)quantize_sort[j] >= maximum_colors);
+  
+                    palette[i] = palette[j];
+                 }
+ @@ -516,7 +525,7 @@ png_set_quantize(png_structrp png_ptr, png_colorp palette,
+           }
+           else
+           {
+ -            int j = num_palette;
+ +            j = num_palette;
+  
+              /* Move all the used colors inside the max limit, and
+               * develop a translation table.
+ @@ -524,13 +533,13 @@ png_set_quantize(png_structrp png_ptr, png_colorp palette,
+              for (i = 0; i < maximum_colors; i++)
+              {
+                 /* Only move the colors we need to */
+ -               if ((int)png_ptr->quantize_sort[i] >= maximum_colors)
+ +               if ((int)quantize_sort[i] >= maximum_colors)
+                 {
+                    png_color tmp_color;
+  
+                    do
+                       j--;
+ -                  while ((int)png_ptr->quantize_sort[j] >= maximum_colors);
+ +                  while ((int)quantize_sort[j] >= maximum_colors);
+  
+                    tmp_color = palette[j];
+                    palette[j] = palette[i];
+ @@ -568,8 +577,8 @@ png_set_quantize(png_structrp png_ptr, png_colorp palette,
+                 }
+              }
+           }
+ -         png_free(png_ptr, png_ptr->quantize_sort);
+ -         png_ptr->quantize_sort = NULL;
+ +         png_free(png_ptr, quantize_sort);
+ +
+        }
+        else
+        {
+ @@ -4925,13 +4934,8 @@ png_do_read_transformations(png_structrp png_ptr, png_row_infop row_info)
+  
+  #ifdef PNG_READ_QUANTIZE_SUPPORTED
+     if ((png_ptr->transformations & PNG_QUANTIZE) != 0)
+ -   {
+        png_do_quantize(row_info, png_ptr->row_buf + 1,
+            png_ptr->palette_lookup, png_ptr->quantize_index);
+ -
+ -      if (row_info->rowbytes == 0)
+ -         png_error(png_ptr, "png_do_quantize returned rowbytes=0");
+ -   }
+  #endif /* READ_QUANTIZE */
+  
+  #ifdef PNG_READ_EXPAND_16_SUPPORTED
+ diff --git a/pngstruct.h b/pngstruct.h
+ index 7c38464..105a6c1 100644
+ --- a/pngstruct.h
+ +++ b/pngstruct.h
+ @@ -421,7 +421,6 @@ struct png_struct_def
+  
+  #ifdef PNG_READ_QUANTIZE_SUPPORTED
+  /* The following three members were added at version 1.0.14 and 1.2.4 */
+ -   png_bytep quantize_sort;          /* working sort array */
+     png_bytep index_to_palette;       /* where the original index currently is
+                                          in the palette */
+     png_bytep palette_to_index;       /* which original index points to this
+ -- 
+ 
```

<details><summary>修复前上下文窗口（展开）</summary>

```diff
/* patch context - source file unavailable */
/* ... line 0 ... */
```

</details>

<details><summary>修复后上下文窗口（展开）</summary>

```diff
/* patch context - source file unavailable */
/* ... line 1 ... */
    1  diff --git a/pngrtran.c b/pngrtran.c
    2  index 1526123..072db9a 100644
    3  --- a/pngrtran.c
    4  +++ b/pngrtran.c
    5  @@ -439,9 +439,19 @@ png_set_quantize(png_structrp png_ptr, png_colorp palette,
    6      {
    7         int i;
    8   
    9  +      /* Initialize the array to index colors.
   10  +       *
   11  +       * Ensure quantize_index can fit 256 elements (PNG_MAX_PALETTE_LENGTH)
   12  +       * rather than num_palette elements. This is to prevent buffer overflows
   13  +       * caused by malformed PNG files with out-of-range palette indices.
   14  +       *
   15  +       * Be careful to avoid leaking memory. Applications are allowed to call
   16  +       * this function more than once per png_struct.
   17  +       */
   18  +      png_free(png_ptr, png_ptr->quantize_index);
   19         png_ptr->quantize_index = (png_bytep)png_malloc(png_ptr,
   20  -          (png_alloc_size_t)num_palette);
   21  -      for (i = 0; i < num_palette; i++)
   22  +          PNG_MAX_PALETTE_LENGTH);
   23  +      for (i = 0; i < PNG_MAX_PALETTE_LENGTH; i++)
   24            png_ptr->quantize_index[i] = (png_byte)i;
   25      }
   26   
   27  @@ -453,15 +463,15 @@ png_set_quantize(png_structrp png_ptr, png_colorp palette,
   28             * Perhaps not the best solution, but good enough.
   29             */
   30   
   31  -         int i;
   32  +         png_bytep quantize_sort;
   33  +         int i, j;
   34   
   35  -         /* Initialize an array to sort colors */
   36  -         png_ptr->quantize_sort = (png_bytep)png_malloc(png_ptr,
   37  +         /* Initialize the local array to sort colors. */
   38  +         quantize_sort = (png_bytep)png_malloc(png_ptr,
   39                (png_alloc_size_t)num_palette);
   40   
   41  -         /* Initialize the quantize_sort array */
   42            for (i = 0; i < num_palette; i++)
   43  -            png_ptr->quantize_sort[i] = (png_byte)i;
   44  +            quantize_sort[i] = (png_byte)i;
   45   
   46            /* Find the least used palette entries by starting a
   47             * bubble sort, and running it until we have sorted
   48  @@ -473,19 +483,18 @@ png_set_quantize(png_structrp png_ptr, png_colorp palette,
   49            for (i = num_palette - 1; i >= maximum_colors; i--)
   50            {
   51               int done; /* To stop early if the list is pre-sorted */
   52  -            int j;
   53   
   54               done = 1;
   55               for (j = 0; j < i; j++)
   56               {
   57  -               if (histogram[png_ptr->quantize_sort[j]]
   58  -                   < histogram[png_ptr->quantize_sort[j + 1]])
   59  +               if (histogram[quantize_sort[j]]
   60  +                   < histogram[quantize_sort[j + 1]])
   61                  {
   62                     png_byte t;
   63   
   64  -                  t = png_ptr->quantize_sort[j];
   65  -                  png_ptr->quantize_sort[j] = png_ptr->quantize_sort[j + 1];
   66  -                  png_ptr->quantize_sort[j + 1] = t;
   67  +                  t = quantize_sort[j];
   68  +                  quantize_sort[j] = quantize_sort[j + 1];
   69  +                  quantize_sort[j + 1] = t;
   70                     done = 0;
   71                  }
   72               }
   73  @@ -497,18 +506,18 @@ png_set_quantize(png_structrp png_ptr, png_colorp palette,
   74            /* Swap the palette around, and set up a table, if necessary */
   75            if (full_quantize != 0)
   76            {
   77  -            int j = num_palette;
   78  +            j = num_palette;
   79   
   80               /* Put all the useful colors within the max, but don't
   81                * move the others.
   82                */
   83               for (i = 0; i < maximum_colors; i++)
   84               {
   85  -               if ((int)png_ptr->quantize_sort[i] >= maximum_colors)
   86  +               if ((int)quantize_sort[i] >= maximum_colors)
   87                  {
   88                     do
   89                        j--;
   90  -                  while ((int)png_ptr->quantize_sort[j] >= maximum_colors);
   91  +                  while ((int)quantize_sort[j] >= maximum_colors);
   92   
   93                     palette[i] = palette[j];
   94                  }
   95  @@ -516,7 +525,7 @@ png_set_quantize(png_structrp png_ptr, png_colorp palette,
   96            }
   97            else
   98            {
   99  -            int j = num_palette;
  100  +            j = num_palette;
  101   
  102               /* Move all the used colors inside the max limit, and
  103                * develop a translation table.
  104  @@ -524,13 +533,13 @@ png_set_quantize(png_structrp png_ptr, png_colorp palette,
  105               for (i = 0; i < maximum_colors; i++)
  106               {
  107                  /* Only move the colors we need to */
  108  -               if ((int)png_ptr->quantize_sort[i] >= maximum_colors)
  109  +               if ((int)quantize_sort[i] >= maximum_colors)
  110                  {
  111                     png_color tmp_color;
  112   
  113                     do
  114                        j--;
  115  -                  while ((int)png_ptr->quantize_sort[j] >= maximum_colors);
  116  +                  while ((int)quantize_sort[j] >= maximum_colors);
  117   
  118                     tmp_color = palette[j];
  119                     palette[j] = palette[i];
  120  @@ -568,8 +577,8 @@ png_set_quantize(png_structrp png_ptr, png_colorp palette,
  121                  }
  122               }
  123            }
  124  -         png_free(png_ptr, png_ptr->quantize_sort);
  125  -         png_ptr->quantize_sort = NULL;
  126  +         png_free(png_ptr, quantize_sort);
  127  +
  128         }
  129         else
  130         {
  131  @@ -4925,13 +4934,8 @@ png_do_read_transformations(png_structrp png_ptr, png_row_infop row_info)
  132   
  133   #ifdef PNG_READ_QUANTIZE_SUPPORTED
  134      if ((png_ptr->transformations & PNG_QUANTIZE) != 0)
  135  -   {
  136         png_do_quantize(row_info, png_ptr->row_buf + 1,
  137             png_ptr->palette_lookup, png_ptr->quantize_index);
  138  -
  139  -      if (row_info->rowbytes == 0)
  140  -         png_error(png_ptr, "png_do_quantize returned rowbytes=0");
  141  -   }
  142   #endif /* READ_QUANTIZE */
  143   
  144   #ifdef PNG_READ_EXPAND_16_SUPPORTED
  145  diff --git a/pngstruct.h b/pngstruct.h
  146  index 7c38464..105a6c1 100644
  147  --- a/pngstruct.h
  148  +++ b/pngstruct.h
  149  @@ -421,7 +421,6 @@ struct png_struct_def
  150   
  151   #ifdef PNG_READ_QUANTIZE_SUPPORTED
  152   /* The following three members were added at version 1.0.14 and 1.2.4 */
  153  -   png_bytep quantize_sort;          /* working sort array */
  154      png_bytep index_to_palette;       /* where the original index currently is
  155                                           in the palette */
  156      png_bytep palette_to_index;       /* which original index points to this
  157  -- 
  158
```

</details>


---

### 2. `（无函数名）`

**文件**：`CVE-2025-64506.patch`  |  **变更**：+16 / -0 行  |  ⚠️ 仅 diff 上下文（源文件不可用，代码不完整）

**Hunk 位置**：`@@ -0,0 +1,16 @@`


#### 代码变更（diff 上下文，源文件不可用）

```diff
+ diff --git a/pngwrite.c b/pngwrite.c
+ index 923a0b0..cb72816 100644
+ --- a/pngwrite.c
+ +++ b/pngwrite.c
+ @@ -2132,8 +2132,7 @@ png_image_write_main(png_voidp argument)
+      * before it is written.  This only applies when the input is 16-bit and
+      * either there is an alpha channel or it is converted to 8-bit.
+      */
+ -   if ((linear != 0 && alpha != 0 ) ||
+ -       (colormap == 0 && display->convert_to_8bit != 0))
+ +   if (linear != 0 && (alpha != 0 || display->convert_to_8bit != 0))
+     {
+        png_bytep row = png_voidcast(png_bytep, png_malloc(png_ptr,
+            png_get_rowbytes(png_ptr, info_ptr)));
+ -- 
+ 
```

<details><summary>修复前上下文窗口（展开）</summary>

```diff
/* patch context - source file unavailable */
/* ... line 0 ... */
```

</details>

<details><summary>修复后上下文窗口（展开）</summary>

```diff
/* patch context - source file unavailable */
/* ... line 1 ... */
    1  diff --git a/pngwrite.c b/pngwrite.c
    2  index 923a0b0..cb72816 100644
    3  --- a/pngwrite.c
    4  +++ b/pngwrite.c
    5  @@ -2132,8 +2132,7 @@ png_image_write_main(png_voidp argument)
    6       * before it is written.  This only applies when the input is 16-bit and
    7       * either there is an alpha channel or it is converted to 8-bit.
    8       */
    9  -   if ((linear != 0 && alpha != 0 ) ||
   10  -       (colormap == 0 && display->convert_to_8bit != 0))
   11  +   if (linear != 0 && (alpha != 0 || display->convert_to_8bit != 0))
   12      {
   13         png_bytep row = png_voidcast(png_bytep, png_malloc(png_ptr,
   14             png_get_rowbytes(png_ptr, info_ptr)));
   15  -- 
   16
```

</details>


---

### 3. `（无函数名）`

**文件**：`CVE-2025-64720.patch`  |  **变更**：+71 / -0 行  |  ⚠️ 仅 diff 上下文（源文件不可用，代码不完整）

**Hunk 位置**：`@@ -0,0 +1,71 @@`


#### 代码变更（diff 上下文，源文件不可用）

```diff
+ diff --git a/pngrtran.c b/pngrtran.c
+ index 072db9a..dbfeac8 100644
+ --- a/pngrtran.c
+ +++ b/pngrtran.c
+ @@ -1699,19 +1699,51 @@ png_init_read_transformations(png_structrp png_ptr)
+                    }
+                    else /* if (png_ptr->trans_alpha[i] != 0xff) */
+                    {
+ -                     png_byte v, w;
+ -
+ -                     v = png_ptr->gamma_to_1[palette[i].red];
+ -                     png_composite(w, v, png_ptr->trans_alpha[i], back_1.red);
+ -                     palette[i].red = png_ptr->gamma_from_1[w];
+ -
+ -                     v = png_ptr->gamma_to_1[palette[i].green];
+ -                     png_composite(w, v, png_ptr->trans_alpha[i], back_1.green);
+ -                     palette[i].green = png_ptr->gamma_from_1[w];
+ -
+ -                     v = png_ptr->gamma_to_1[palette[i].blue];
+ -                     png_composite(w, v, png_ptr->trans_alpha[i], back_1.blue);
+ -                     palette[i].blue = png_ptr->gamma_from_1[w];
+ +                     if ((png_ptr->flags & PNG_FLAG_OPTIMIZE_ALPHA) != 0)
+ +                     {
+ +                        /* Premultiply only:
+ +                         * component = round((component * alpha) / 255)
+ +                         */
+ +                        png_uint_32 component;
+ +
+ +                        component = png_ptr->gamma_to_1[palette[i].red];
+ +                        component =
+ +                            (component * png_ptr->trans_alpha[i] + 128) / 255;
+ +                        palette[i].red = png_ptr->gamma_from_1[component];
+ +
+ +                        component = png_ptr->gamma_to_1[palette[i].green];
+ +                        component =
+ +                            (component * png_ptr->trans_alpha[i] + 128) / 255;
+ +                        palette[i].green = png_ptr->gamma_from_1[component];
+ +
+ +                        component = png_ptr->gamma_to_1[palette[i].blue];
+ +                        component =
+ +                            (component * png_ptr->trans_alpha[i] + 128) / 255;
+ +                        palette[i].blue = png_ptr->gamma_from_1[component];
+ +                     }
+ +                     else
+ +                     {
+ +                        /* Composite with background color:
+ +                         * component =
+ +                         *    alpha * component + (1 - alpha) * background
+ +                         */
+ +                        png_byte v, w;
+ +
+ +                        v = png_ptr->gamma_to_1[palette[i].red];
+ +                        png_composite(w, v,
+ +                            png_ptr->trans_alpha[i], back_1.red);
+ +                        palette[i].red = png_ptr->gamma_from_1[w];
+ +
+ +                        v = png_ptr->gamma_to_1[palette[i].green];
+ +                        png_composite(w, v,
+ +                            png_ptr->trans_alpha[i], back_1.green);
+ +                        palette[i].green = png_ptr->gamma_from_1[w];
+ +
+ +                        v = png_ptr->gamma_to_1[palette[i].blue];
+ +                        png_composite(w, v,
+ +                            png_ptr->trans_alpha[i], back_1.blue);
+ +                        palette[i].blue = png_ptr->gamma_from_1[w];
+ +                     }
+                    }
+                 }
+                 else
+ -- 
+ 
```

<details><summary>修复前上下文窗口（展开）</summary>

```diff
/* patch context - source file unavailable */
/* ... line 0 ... */
```

</details>

<details><summary>修复后上下文窗口（展开）</summary>

```diff
/* patch context - source file unavailable */
/* ... line 1 ... */
    1  diff --git a/pngrtran.c b/pngrtran.c
    2  index 072db9a..dbfeac8 100644
    3  --- a/pngrtran.c
    4  +++ b/pngrtran.c
    5  @@ -1699,19 +1699,51 @@ png_init_read_transformations(png_structrp png_ptr)
    6                     }
    7                     else /* if (png_ptr->trans_alpha[i] != 0xff) */
    8                     {
    9  -                     png_byte v, w;
   10  -
   11  -                     v = png_ptr->gamma_to_1[palette[i].red];
   12  -                     png_composite(w, v, png_ptr->trans_alpha[i], back_1.red);
   13  -                     palette[i].red = png_ptr->gamma_from_1[w];
   14  -
   15  -                     v = png_ptr->gamma_to_1[palette[i].green];
   16  -                     png_composite(w, v, png_ptr->trans_alpha[i], back_1.green);
   17  -                     palette[i].green = png_ptr->gamma_from_1[w];
   18  -
   19  -                     v = png_ptr->gamma_to_1[palette[i].blue];
   20  -                     png_composite(w, v, png_ptr->trans_alpha[i], back_1.blue);
   21  -                     palette[i].blue = png_ptr->gamma_from_1[w];
   22  +                     if ((png_ptr->flags & PNG_FLAG_OPTIMIZE_ALPHA) != 0)
   23  +                     {
   24  +                        /* Premultiply only:
   25  +                         * component = round((component * alpha) / 255)
   26  +                         */
   27  +                        png_uint_32 component;
   28  +
   29  +                        component = png_ptr->gamma_to_1[palette[i].red];
   30  +                        component =
   31  +                            (component * png_ptr->trans_alpha[i] + 128) / 255;
   32  +                        palette[i].red = png_ptr->gamma_from_1[component];
   33  +
   34  +                        component = png_ptr->gamma_to_1[palette[i].green];
   35  +                        component =
   36  +                            (component * png_ptr->trans_alpha[i] + 128) / 255;
   37  +                        palette[i].green = png_ptr->gamma_from_1[component];
   38  +
   39  +                        component = png_ptr->gamma_to_1[palette[i].blue];
   40  +                        component =
   41  +                            (component * png_ptr->trans_alpha[i] + 128) / 255;
   42  +                        palette[i].blue = png_ptr->gamma_from_1[component];
   43  +                     }
   44  +                     else
   45  +                     {
   46  +                        /* Composite with background color:
   47  +                         * component =
   48  +                         *    alpha * component + (1 - alpha) * background
   49  +                         */
   50  +                        png_byte v, w;
   51  +
   52  +                        v = png_ptr->gamma_to_1[palette[i].red];
   53  +                        png_composite(w, v,
   54  +                            png_ptr->trans_alpha[i], back_1.red);
   55  +                        palette[i].red = png_ptr->gamma_from_1[w];
   56  +
   57  +                        v = png_ptr->gamma_to_1[palette[i].green];
   58  +                        png_composite(w, v,
   59  +                            png_ptr->trans_alpha[i], back_1.green);
   60  +                        palette[i].green = png_ptr->gamma_from_1[w];
   61  +
   62  +                        v = png_ptr->gamma_to_1[palette[i].blue];
   63  +                        png_composite(w, v,
   64  +                            png_ptr->trans_alpha[i], back_1.blue);
   65  +                        palette[i].blue = png_ptr->gamma_from_1[w];
   66  +                     }
   67                     }
   68                  }
   69                  else
   70  -- 
   71
```

</details>


---

### 4. `（无函数名）`

**文件**：`CVE-2025-65018.patch`  |  **变更**：+111 / -0 行  |  ⚠️ 仅 diff 上下文（源文件不可用，代码不完整）

**Hunk 位置**：`@@ -0,0 +1,111 @@`


#### 代码变更（diff 上下文，源文件不可用）

```diff
+ diff --git a/pngread.c b/pngread.c
+ index a7a644e..7f9c5de 100644
+ --- a/pngread.c
+ +++ b/pngread.c
+ @@ -3521,6 +3521,54 @@ png_image_read_colormapped(png_voidp argument)
+     }
+  }
+  
+ +/* Row reading for interlaced 16-to-8 bit depth conversion with local buffer. */
+ +static int
+ +png_image_read_direct_scaled(png_voidp argument)
+ +{
+ +   png_image_read_control *display = png_voidcast(png_image_read_control*,
+ +       argument);
+ +   png_imagep image = display->image;
+ +   png_structrp png_ptr = image->opaque->png_ptr;
+ +   png_bytep local_row = png_voidcast(png_bytep, display->local_row);
+ +   png_bytep first_row = png_voidcast(png_bytep, display->first_row);
+ +   ptrdiff_t row_bytes = display->row_bytes;
+ +   int passes;
+ +
+ +   /* Handle interlacing. */
+ +   switch (png_ptr->interlaced)
+ +   {
+ +      case PNG_INTERLACE_NONE:
+ +         passes = 1;
+ +         break;
+ +
+ +      case PNG_INTERLACE_ADAM7:
+ +         passes = PNG_INTERLACE_ADAM7_PASSES;
+ +         break;
+ +
+ +      default:
+ +         png_error(png_ptr, "unknown interlace type");
+ +   }
+ +
+ +   /* Read each pass using local_row as intermediate buffer. */
+ +   while (--passes >= 0)
+ +   {
+ +      png_uint_32 y = image->height;
+ +      png_bytep output_row = first_row;
+ +
+ +      for (; y > 0; --y)
+ +      {
+ +         /* Read into local_row (gets transformed 8-bit data). */
+ +         png_read_row(png_ptr, local_row, NULL);
+ +
+ +         /* Copy from local_row to user buffer. */
+ +         memcpy(output_row, local_row, (size_t)row_bytes);
+ +         output_row += row_bytes;
+ +      }
+ +   }
+ +
+ +   return 1;
+ +}
+ +
+  /* Just the row reading part of png_image_read. */
+  static int
+  png_image_read_composite(png_voidp argument)
+ @@ -3942,6 +3990,7 @@ png_image_read_direct(png_voidp argument)
+     int linear = (format & PNG_FORMAT_FLAG_LINEAR) != 0;
+     int do_local_compose = 0;
+     int do_local_background = 0; /* to avoid double gamma correction bug */
+ +   int do_local_scale = 0; /* for interlaced 16-to-8 bit conversion */
+     int passes = 0;
+  
+     /* Add transforms to ensure the correct output format is produced then check
+ @@ -4068,8 +4117,16 @@ png_image_read_direct(png_voidp argument)
+              png_set_expand_16(png_ptr);
+  
+           else /* 8-bit output */
+ +         {
+              png_set_scale_16(png_ptr);
+  
+ +            /* For interlaced images, use local_row buffer to avoid overflow
+ +             * in png_combine_row() which writes using IHDR bit-depth.
+ +             */
+ +            if (png_ptr->interlaced != 0)
+ +               do_local_scale = 1;
+ +         }
+ +
+           change &= ~PNG_FORMAT_FLAG_LINEAR;
+        }
+  
+ @@ -4345,6 +4402,24 @@ png_image_read_direct(png_voidp argument)
+        return result;
+     }
+  
+ +   else if (do_local_scale != 0)
+ +   {
+ +      /* For interlaced 16-to-8 conversion, use an intermediate row buffer
+ +       * to avoid buffer overflows in png_combine_row. The local_row is sized
+ +       * for the transformed (8-bit) output, preventing the overflow that would
+ +       * occur if png_combine_row wrote 16-bit data directly to the user buffer.
+ +       */
+ +      int result;
+ +      png_voidp row = png_malloc(png_ptr, png_get_rowbytes(png_ptr, info_ptr));
+ +
+ +      display->local_row = row;
+ +      result = png_safe_execute(image, png_image_read_direct_scaled, display);
+ +      display->local_row = NULL;
+ +      png_free(png_ptr, row);
+ +
+ +      return result;
+ +   }
+ +
+     else
+     {
+        png_alloc_size_t row_bytes = (png_alloc_size_t)display->row_bytes;
+ -- 
+ 
```

<details><summary>修复前上下文窗口（展开）</summary>

```diff
/* patch context - source file unavailable */
/* ... line 0 ... */
```

</details>

<details><summary>修复后上下文窗口（展开）</summary>

```diff
/* patch context - source file unavailable */
/* ... line 1 ... */
    1  diff --git a/pngread.c b/pngread.c
    2  index a7a644e..7f9c5de 100644
    3  --- a/pngread.c
    4  +++ b/pngread.c
    5  @@ -3521,6 +3521,54 @@ png_image_read_colormapped(png_voidp argument)
    6      }
    7   }
    8   
    9  +/* Row reading for interlaced 16-to-8 bit depth conversion with local buffer. */
   10  +static int
   11  +png_image_read_direct_scaled(png_voidp argument)
   12  +{
   13  +   png_image_read_control *display = png_voidcast(png_image_read_control*,
   14  +       argument);
   15  +   png_imagep image = display->image;
   16  +   png_structrp png_ptr = image->opaque->png_ptr;
   17  +   png_bytep local_row = png_voidcast(png_bytep, display->local_row);
   18  +   png_bytep first_row = png_voidcast(png_bytep, display->first_row);
   19  +   ptrdiff_t row_bytes = display->row_bytes;
   20  +   int passes;
   21  +
   22  +   /* Handle interlacing. */
   23  +   switch (png_ptr->interlaced)
   24  +   {
   25  +      case PNG_INTERLACE_NONE:
   26  +         passes = 1;
   27  +         break;
   28  +
   29  +      case PNG_INTERLACE_ADAM7:
   30  +         passes = PNG_INTERLACE_ADAM7_PASSES;
   31  +         break;
   32  +
   33  +      default:
   34  +         png_error(png_ptr, "unknown interlace type");
   35  +   }
   36  +
   37  +   /* Read each pass using local_row as intermediate buffer. */
   38  +   while (--passes >= 0)
   39  +   {
   40  +      png_uint_32 y = image->height;
   41  +      png_bytep output_row = first_row;
   42  +
   43  +      for (; y > 0; --y)
   44  +      {
   45  +         /* Read into local_row (gets transformed 8-bit data). */
   46  +         png_read_row(png_ptr, local_row, NULL);
   47  +
   48  +         /* Copy from local_row to user buffer. */
   49  +         memcpy(output_row, local_row, (size_t)row_bytes);
   50  +         output_row += row_bytes;
   51  +      }
   52  +   }
   53  +
   54  +   return 1;
   55  +}
   56  +
   57   /* Just the row reading part of png_image_read. */
   58   static int
   59   png_image_read_composite(png_voidp argument)
   60  @@ -3942,6 +3990,7 @@ png_image_read_direct(png_voidp argument)
   61      int linear = (format & PNG_FORMAT_FLAG_LINEAR) != 0;
   62      int do_local_compose = 0;
   63      int do_local_background = 0; /* to avoid double gamma correction bug */
   64  +   int do_local_scale = 0; /* for interlaced 16-to-8 bit conversion */
   65      int passes = 0;
   66   
   67      /* Add transforms to ensure the correct output format is produced then check
   68  @@ -4068,8 +4117,16 @@ png_image_read_direct(png_voidp argument)
   69               png_set_expand_16(png_ptr);
   70   
   71            else /* 8-bit output */
   72  +         {
   73               png_set_scale_16(png_ptr);
   74   
   75  +            /* For interlaced images, use local_row buffer to avoid overflow
   76  +             * in png_combine_row() which writes using IHDR bit-depth.
   77  +             */
   78  +            if (png_ptr->interlaced != 0)
   79  +               do_local_scale = 1;
   80  +         }
   81  +
   82            change &= ~PNG_FORMAT_FLAG_LINEAR;
   83         }
   84   
   85  @@ -4345,6 +4402,24 @@ png_image_read_direct(png_voidp argument)
   86         return result;
   87      }
   88   
   89  +   else if (do_local_scale != 0)
   90  +   {
   91  +      /* For interlaced 16-to-8 conversion, use an intermediate row buffer
   92  +       * to avoid buffer overflows in png_combine_row. The local_row is sized
   93  +       * for the transformed (8-bit) output, preventing the overflow that would
   94  +       * occur if png_combine_row wrote 16-bit data directly to the user buffer.
   95  +       */
   96  +      int result;
   97  +      png_voidp row = png_malloc(png_ptr, png_get_rowbytes(png_ptr, info_ptr));
   98  +
   99  +      display->local_row = row;
  100  +      result = png_safe_execute(image, png_image_read_direct_scaled, display);
  101  +      display->local_row = NULL;
  102  +      png_free(png_ptr, row);
  103  +
  104  +      return result;
  105  +   }
  106  +
  107      else
  108      {
  109         png_alloc_size_t row_bytes = (png_alloc_size_t)display->row_bytes;
  110  -- 
  111
```

</details>


---

### 5. `def move_file(src_path, dst_path):`

**文件**：`install.py`  |  **变更**：+5 / -1 行  |  ⚠️ 仅 diff 上下文（源文件不可用，代码不完整）

**Hunk 位置**：`@@ -38,7 +38,11 @@ def move_file(src_path, dst_path):`


#### 代码变更（diff 上下文，源文件不可用）

```diff
-         "libpng_optimize.patch"
+         "libpng_optimize.patch",
+         "CVE-2025-64505.patch",
+         "CVE-2025-64506.patch",
+         "CVE-2025-64720.patch",
+         "CVE-2025-65018.patch"
```

<details><summary>修复前上下文窗口（展开）</summary>

```python
/* patch context - source file unavailable */
/* ... line 38 ... */
   38          "backport-libpng-1.6.37-enable-valid.patch",
   39          "pnglibconf.h",
   40          "CVE-2018-14048.patch",
   41          "libpng_optimize.patch"
   42      ]
   43      for file in files:
   44          src_file = os.path.join(src_path, file)
```

</details>

<details><summary>修复后上下文窗口（展开）</summary>

```python
/* patch context - source file unavailable */
/* ... line 38 ... */
   38          "backport-libpng-1.6.37-enable-valid.patch",
   39          "pnglibconf.h",
   40          "CVE-2018-14048.patch",
   41          "libpng_optimize.patch",
   42          "CVE-2025-64505.patch",
   43          "CVE-2025-64506.patch",
   44          "CVE-2025-64720.patch",
   45          "CVE-2025-65018.patch"
   46      ]
   47      for file in files:
   48          src_file = os.path.join(src_path, file)
```

</details>


---

### 6. `def do_patch(target_dir):`

**文件**：`install.py`  |  **变更**：+5 / -1 行  |  ⚠️ 仅 diff 上下文（源文件不可用，代码不完整）

**Hunk 位置**：`@@ -64,7 +68,11 @@ def do_patch(target_dir):`


#### 代码变更（diff 上下文，源文件不可用）

```diff
-         "libpng_optimize.patch"
+         "libpng_optimize.patch",
+         "CVE-2025-64505.patch",
+         "CVE-2025-64506.patch",
+         "CVE-2025-64720.patch",
+         "CVE-2025-65018.patch"
```

<details><summary>修复前上下文窗口（展开）</summary>

```python
/* patch context - source file unavailable */
/* ... line 64 ... */
   64          "libpng-multilib.patch",
   65          "backport-libpng-1.6.37-enable-valid.patch",
   66          "CVE-2018-14048.patch",
   67          "libpng_optimize.patch"
   68      ]
   69  
   70      for patch in patch_file:
```

</details>

<details><summary>修复后上下文窗口（展开）</summary>

```python
/* patch context - source file unavailable */
/* ... line 68 ... */
   68          "libpng-multilib.patch",
   69          "backport-libpng-1.6.37-enable-valid.patch",
   70          "CVE-2018-14048.patch",
   71          "libpng_optimize.patch",
   72          "CVE-2025-64505.patch",
   73          "CVE-2025-64506.patch",
   74          "CVE-2025-64720.patch",
   75          "CVE-2025-65018.patch"
   76      ]
   77  
   78      for patch in patch_file:
```

</details>


---

<a id="cve202564505"></a>

## CVE-2025-64505  ·  third_party_libpng  ·  无

**参考链接**：<https://gitcode.com/openharmony/third_party_libpng/blob/d5bb6e40a0c0a2b1b388b122f85b7632dbd58fdc/CVE-2025-64505.patch>

**标题**：漏洞修复CVE-2025-64505、CVE-2025-64506、CVE-2025-64720、CVE-2025-65018

**漏洞描述**：

> Signed-off-by: zhwang0 <zhwang0@163.com>


共涉及 **3** 个函数／代码区域：

### 1. `png_set_quantize(png_structrp png_ptr, png_colorp palette,`

**文件**：`pngrtran.c`  |  **变更**：+30 / -21 行  |  ✅ 完整函数体（源文件已获取）

**Hunk 位置**：`@@ -439,9 +439,19 @@ png_set_quantize(png_structrp png_ptr, png_colorp palette,`、`@@ -453,15 +463,15 @@ png_set_quantize(png_structrp png_ptr, png_colorp palette,`、`@@ -473,19 +483,18 @@ png_set_quantize(png_structrp png_ptr, png_colorp palette,`、`@@ -497,18 +506,18 @@ png_set_quantize(png_structrp png_ptr, png_colorp palette,`、`@@ -516,7 +525,7 @@ png_set_quantize(png_structrp png_ptr, png_colorp palette,`、`@@ -524,13 +533,13 @@ png_set_quantize(png_structrp png_ptr, png_colorp palette,`、`@@ -568,8 +577,8 @@ png_set_quantize(png_structrp png_ptr, png_colorp palette,`


#### 漏洞函数（修复前）

```c
/* patch context - source file unavailable */
/* ... line 439 ... */
  439     {
  440        int i;
  441  
  442        png_ptr->quantize_index = (png_bytep)png_malloc(png_ptr,
  443            (png_alloc_size_t)num_palette);
  444        for (i = 0; i < num_palette; i++)
  445           png_ptr->quantize_index[i] = (png_byte)i;
  446     }
  447  
/* ... line 453 ... */
  453            * Perhaps not the best solution, but good enough.
  454            */
  455  
  456           int i;
  457  
  458           /* Initialize an array to sort colors */
  459           png_ptr->quantize_sort = (png_bytep)png_malloc(png_ptr,
  460               (png_alloc_size_t)num_palette);
  461  
  462           /* Initialize the quantize_sort array */
  463           for (i = 0; i < num_palette; i++)
  464              png_ptr->quantize_sort[i] = (png_byte)i;
  465  
  466           /* Find the least used palette entries by starting a
  467            * bubble sort, and running it until we have sorted
/* ... line 473 ... */
  473           for (i = num_palette - 1; i >= maximum_colors; i--)
  474           {
  475              int done; /* To stop early if the list is pre-sorted */
  476              int j;
  477  
  478              done = 1;
  479              for (j = 0; j < i; j++)
  480              {
  481                 if (histogram[png_ptr->quantize_sort[j]]
  482                     < histogram[png_ptr->quantize_sort[j + 1]])
  483                 {
  484                    png_byte t;
  485  
  486                    t = png_ptr->quantize_sort[j];
  487                    png_ptr->quantize_sort[j] = png_ptr->quantize_sort[j + 1];
  488                    png_ptr->quantize_sort[j + 1] = t;
  489                    done = 0;
  490                 }
  491              }
/* ... line 497 ... */
  497           /* Swap the palette around, and set up a table, if necessary */
  498           if (full_quantize != 0)
  499           {
  500              int j = num_palette;
  501  
  502              /* Put all the useful colors within the max, but don't
  503               * move the others.
  504               */
  505              for (i = 0; i < maximum_colors; i++)
  506              {
  507                 if ((int)png_ptr->quantize_sort[i] >= maximum_colors)
  508                 {
  509                    do
  510                       j--;
  511                    while ((int)png_ptr->quantize_sort[j] >= maximum_colors);
  512  
  513                    palette[i] = palette[j];
  514                 }
/* ... line 516 ... */
  516           }
  517           else
  518           {
  519              int j = num_palette;
  520  
  521              /* Move all the used colors inside the max limit, and
  522               * develop a translation table.
/* ... line 524 ... */
  524              for (i = 0; i < maximum_colors; i++)
  525              {
  526                 /* Only move the colors we need to */
  527                 if ((int)png_ptr->quantize_sort[i] >= maximum_colors)
  528                 {
  529                    png_color tmp_color;
  530  
  531                    do
  532                       j--;
  533                    while ((int)png_ptr->quantize_sort[j] >= maximum_colors);
  534  
  535                    tmp_color = palette[j];
  536                    palette[j] = palette[i];
/* ... line 568 ... */
  568                 }
  569              }
  570           }
  571           png_free(png_ptr, png_ptr->quantize_sort);
  572           png_ptr->quantize_sort = NULL;
  573        }
  574        else
  575        {
```


#### 修复函数（修复后）

```c
/* patch context - source file unavailable */
/* ... line 439 ... */
  439     {
  440        int i;
  441  
  442        /* Initialize the array to index colors.
  443         *
  444         * Ensure quantize_index can fit 256 elements (PNG_MAX_PALETTE_LENGTH)
  445         * rather than num_palette elements. This is to prevent buffer overflows
  446         * caused by malformed PNG files with out-of-range palette indices.
  447         *
  448         * Be careful to avoid leaking memory. Applications are allowed to call
  449         * this function more than once per png_struct.
  450         */
  451        png_free(png_ptr, png_ptr->quantize_index);
  452        png_ptr->quantize_index = (png_bytep)png_malloc(png_ptr,
  453            PNG_MAX_PALETTE_LENGTH);
  454        for (i = 0; i < PNG_MAX_PALETTE_LENGTH; i++)
  455           png_ptr->quantize_index[i] = (png_byte)i;
  456     }
  457  
/* ... line 463 ... */
  463            * Perhaps not the best solution, but good enough.
  464            */
  465  
  466           png_bytep quantize_sort;
  467           int i, j;
  468  
  469           /* Initialize the local array to sort colors. */
  470           quantize_sort = (png_bytep)png_malloc(png_ptr,
  471               (png_alloc_size_t)num_palette);
  472  
  473           for (i = 0; i < num_palette; i++)
  474              quantize_sort[i] = (png_byte)i;
  475  
  476           /* Find the least used palette entries by starting a
  477            * bubble sort, and running it until we have sorted
/* ... line 483 ... */
  483           for (i = num_palette - 1; i >= maximum_colors; i--)
  484           {
  485              int done; /* To stop early if the list is pre-sorted */
  486  
  487              done = 1;
  488              for (j = 0; j < i; j++)
  489              {
  490                 if (histogram[quantize_sort[j]]
  491                     < histogram[quantize_sort[j + 1]])
  492                 {
  493                    png_byte t;
  494  
  495                    t = quantize_sort[j];
  496                    quantize_sort[j] = quantize_sort[j + 1];
  497                    quantize_sort[j + 1] = t;
  498                    done = 0;
  499                 }
  500              }
/* ... line 506 ... */
  506           /* Swap the palette around, and set up a table, if necessary */
  507           if (full_quantize != 0)
  508           {
  509              j = num_palette;
  510  
  511              /* Put all the useful colors within the max, but don't
  512               * move the others.
  513               */
  514              for (i = 0; i < maximum_colors; i++)
  515              {
  516                 if ((int)quantize_sort[i] >= maximum_colors)
  517                 {
  518                    do
  519                       j--;
  520                    while ((int)quantize_sort[j] >= maximum_colors);
  521  
  522                    palette[i] = palette[j];
  523                 }
/* ... line 525 ... */
  525           }
  526           else
  527           {
  528              j = num_palette;
  529  
  530              /* Move all the used colors inside the max limit, and
  531               * develop a translation table.
/* ... line 533 ... */
  533              for (i = 0; i < maximum_colors; i++)
  534              {
  535                 /* Only move the colors we need to */
  536                 if ((int)quantize_sort[i] >= maximum_colors)
  537                 {
  538                    png_color tmp_color;
  539  
  540                    do
  541                       j--;
  542                    while ((int)quantize_sort[j] >= maximum_colors);
  543  
  544                    tmp_color = palette[j];
  545                    palette[j] = palette[i];
/* ... line 577 ... */
  577                 }
  578              }
  579           }
  580           png_free(png_ptr, quantize_sort);
  581  
  582        }
  583        else
  584        {
```


#### 关键变更行

```diff
-           (png_alloc_size_t)num_palette);
-       for (i = 0; i < num_palette; i++)
-          int i;
-          /* Initialize an array to sort colors */
-          png_ptr->quantize_sort = (png_bytep)png_malloc(png_ptr,
-          /* Initialize the quantize_sort array */
-             png_ptr->quantize_sort[i] = (png_byte)i;
-             int j;
-                if (histogram[png_ptr->quantize_sort[j]]
-                    < histogram[png_ptr->quantize_sort[j + 1]])
-                   t = png_ptr->quantize_sort[j];
-                   png_ptr->quantize_sort[j] = png_ptr->quantize_sort[j + 1];
-                   png_ptr->quantize_sort[j + 1] = t;
-             int j = num_palette;
-                if ((int)png_ptr->quantize_sort[i] >= maximum_colors)
-                   while ((int)png_ptr->quantize_sort[j] >= maximum_colors);
-             int j = num_palette;
-                if ((int)png_ptr->quantize_sort[i] >= maximum_colors)
-                   while ((int)png_ptr->quantize_sort[j] >= maximum_colors);
-          png_free(png_ptr, png_ptr->quantize_sort);
-          png_ptr->quantize_sort = NULL;
+       /* Initialize the array to index colors.
+        *
+        * Ensure quantize_index can fit 256 elements (PNG_MAX_PALETTE_LENGTH)
+        * rather than num_palette elements. This is to prevent buffer overflows
+        * caused by malformed PNG files with out-of-range palette indices.
+        *
+        * Be careful to avoid leaking memory. Applications are allowed to call
+        * this function more than once per png_struct.
+        */
+       png_free(png_ptr, png_ptr->quantize_index);
+           PNG_MAX_PALETTE_LENGTH);
+       for (i = 0; i < PNG_MAX_PALETTE_LENGTH; i++)
+          png_bytep quantize_sort;
+          int i, j;
+          /* Initialize the local array to sort colors. */
+          quantize_sort = (png_bytep)png_malloc(png_ptr,
+             quantize_sort[i] = (png_byte)i;
+                if (histogram[quantize_sort[j]]
+                    < histogram[quantize_sort[j + 1]])
+                   t = quantize_sort[j];
+                   quantize_sort[j] = quantize_sort[j + 1];
+                   quantize_sort[j + 1] = t;
+             j = num_palette;
+                if ((int)quantize_sort[i] >= maximum_colors)
+                   while ((int)quantize_sort[j] >= maximum_colors);
+             j = num_palette;
+                if ((int)quantize_sort[i] >= maximum_colors)
+                   while ((int)quantize_sort[j] >= maximum_colors);
+          png_free(png_ptr, quantize_sort);
+ 
```


---

### 2. `png_do_read_transformations(png_structrp png_ptr, png_row_infop row_info)`

**文件**：`pngrtran.c`  |  **变更**：+0 / -5 行  |  ✅ 完整函数体（源文件已获取）

**Hunk 位置**：`@@ -4925,13 +4934,8 @@ png_do_read_transformations(png_structrp png_ptr, png_row_infop row_info)`


#### 漏洞函数（修复前）

```c
void /* PRIVATE */
png_do_read_transformations(png_structrp png_ptr, png_row_infop row_info)
{
   png_debug(1, "in png_do_read_transformations");

   if (png_ptr->row_buf == NULL)
   {
      /* Prior to 1.5.4 this output row/pass where the NULL pointer is, but this
       * error is incredibly rare and incredibly easy to debug without this
       * information.
       */
      png_error(png_ptr, "NULL row buffer");
   }

   /* The following is debugging; prior to 1.5.4 the code was never compiled in;
    * in 1.5.4 PNG_FLAG_DETECT_UNINITIALIZED was added and the macro
    * PNG_WARN_UNINITIALIZED_ROW removed.  In 1.6 the new flag is set only for
    * all transformations, however in practice the ROW_INIT always gets done on
    * demand, if necessary.
    */
   if ((png_ptr->flags & PNG_FLAG_DETECT_UNINITIALIZED) != 0 &&
       (png_ptr->flags & PNG_FLAG_ROW_INIT) == 0)
   {
      /* Application has failed to call either png_read_start_image() or
       * png_read_update_info() after setting transforms that expand pixels.
       * This check added to libpng-1.2.19 (but not enabled until 1.5.4).
       */
      png_error(png_ptr, "Uninitialized row");
   }

#ifdef PNG_READ_EXPAND_SUPPORTED
   if ((png_ptr->transformations & PNG_EXPAND) != 0)
   {
      if (row_info->color_type == PNG_COLOR_TYPE_PALETTE)
      {
#ifdef PNG_ARM_NEON_INTRINSICS_AVAILABLE
         if ((png_ptr->num_trans > 0) && (png_ptr->bit_depth == 8))
         {
            if (png_ptr->riffled_palette == NULL)
            {
               /* Initialize the accelerated palette expansion. */
               png_ptr->riffled_palette =
                   (png_bytep)png_malloc(png_ptr, 256 * 4);
               png_riffle_palette_neon(png_ptr);
            }
         }
#endif
         png_do_expand_palette(png_ptr, row_info, png_ptr->row_buf + 1,
             png_ptr->palette, png_ptr->trans_alpha, png_ptr->num_trans);
      }

      else
      {
         if (png_ptr->num_trans != 0 &&
             (png_ptr->transformations & PNG_EXPAND_tRNS) != 0)
            png_do_expand(row_info, png_ptr->row_buf + 1,
                &(png_ptr->trans_color));

         else
            png_do_expand(row_info, png_ptr->row_buf + 1, NULL);
      }
   }
#endif

#ifdef PNG_READ_STRIP_ALPHA_SUPPORTED
   if ((png_ptr->transformations & PNG_STRIP_ALPHA) != 0 &&
       (png_ptr->transformations & PNG_COMPOSE) == 0 &&
       (row_info->color_type == PNG_COLOR_TYPE_RGB_ALPHA ||
       row_info->color_type == PNG_COLOR_TYPE_GRAY_ALPHA))
      png_do_strip_channel(row_info, png_ptr->row_buf + 1,
          0 /* at_start == false, because SWAP_ALPHA happens later */);
#endif

#ifdef PNG_READ_RGB_TO_GRAY_SUPPORTED
   if ((png_ptr->transformations & PNG_RGB_TO_GRAY) != 0)
   {
      int rgb_error =
          png_do_rgb_to_gray(png_ptr, row_info,
              png_ptr->row_buf + 1);

      if (rgb_error != 0)
      {
         png_ptr->rgb_to_gray_status=1;
         if ((png_ptr->transformations & PNG_RGB_TO_GRAY) ==
             PNG_RGB_TO_GRAY_WARN)
            png_warning(png_ptr, "png_do_rgb_to_gray found nongray pixel");

         if ((png_ptr->transformations & PNG_RGB_TO_GRAY) ==
             PNG_RGB_TO_GRAY_ERR)
            png_error(png_ptr, "png_do_rgb_to_gray found nongray pixel");
      }
   }
#endif

/* From Andreas Dilger e-mail to png-implement, 26 March 1998:
 *
 *   In most cases, the "simple transparency" should be done prior to doing
 *   gray-to-RGB, or you will have to test 3x as many bytes to check if a
 *   pixel is transparent.  You would also need to make sure that the
 *   transparency information is upgraded to RGB.
 *
 *   To summarize, the current flow is:
 *   - Gray + simple transparency -> compare 1 or 2 gray bytes and composite
 *                                   with background "in place" if transparent,
 *                                   convert to RGB if necessary
 *   - Gray + alpha -> composite with gray background and remove alpha bytes,
 *                                   convert to RGB if necessary
 *
 *   To support RGB backgrounds for gray images we need:
 *   - Gray + simple transparency -> convert to RGB + simple transparency,
 *                                   compare 3 or 6 bytes and composite with
 *                                   background "in place" if transparent
 *                                   (3x compare/pixel compared to doing
 *                                   composite with gray bkgrnd)
 *   - Gray + alpha -> convert to RGB + alpha, composite with background and
 *                                   remove alpha bytes (3x float
 *                                   operations/pixel compared with composite
 *                                   on gray background)
 *
 *  Greg's change will do this.  The reason it wasn't done before is for
 *  performance, as this increases the per-pixel operations.  If we would check
 *  in advance if the background was gray or RGB, and position the gray-to-RGB
 *  transform appropriately, then it would save a lot of work/time.
 */

#ifdef PNG_READ_GRAY_TO_RGB_SUPPORTED
   /* If gray -> RGB, do so now only if background is non-gray; else do later
    * for performance reasons
    */
   if ((png_ptr->transformations & PNG_GRAY_TO_RGB) != 0 &&
       (png_ptr->mode & PNG_BACKGROUND_IS_GRAY) == 0)
      png_do_gray_to_rgb(row_info, png_ptr->row_buf + 1);
#endif

#if defined(PNG_READ_BACKGROUND_SUPPORTED) ||\
   defined(PNG_READ_ALPHA_MODE_SUPPORTED)
   if ((png_ptr->transformations & PNG_COMPOSE) != 0)
      png_do_compose(row_info, png_ptr->row_buf + 1, png_ptr);
#endif

#ifdef PNG_READ_GAMMA_SUPPORTED
   if ((png_ptr->transformations & PNG_GAMMA) != 0 &&
#ifdef PNG_READ_RGB_TO_GRAY_SUPPORTED
      /* Because RGB_TO_GRAY does the gamma transform. */
      (png_ptr->transformations & PNG_RGB_TO_GRAY) == 0 &&
#endif
#if defined(PNG_READ_BACKGROUND_SUPPORTED) ||\
   defined(PNG_READ_ALPHA_MODE_SUPPORTED)
      /* Because PNG_COMPOSE does the gamma transform if there is something to
       * do (if there is an alpha channel or transparency.)
       */
       !((png_ptr->transformations & PNG_COMPOSE) != 0 &&
       ((png_ptr->num_trans != 0) ||
       (png_ptr->color_type & PNG_COLOR_MASK_ALPHA) != 0)) &&
#endif
      /* Because png_init_read_transformations transforms the palette, unless
       * RGB_TO_GRAY will do the transform.
       */
       (png_ptr->color_type != PNG_COLOR_TYPE_PALETTE))
      png_do_gamma(row_info, png_ptr->row_buf + 1, png_ptr);
#endif

#ifdef PNG_READ_STRIP_ALPHA_SUPPORTED
   if ((png_ptr->transformations & PNG_STRIP_ALPHA) != 0 &&
       (png_ptr->transformations & PNG_COMPOSE) != 0 &&
       (row_info->color_type == PNG_COLOR_TYPE_RGB_ALPHA ||
       row_info->color_type == PNG_COLOR_TYPE_GRAY_ALPHA))
      png_do_strip_channel(row_info, png_ptr->row_buf + 1,
          0 /* at_start == false, because SWAP_ALPHA happens later */);
#endif

#ifdef PNG_READ_ALPHA_MODE_SUPPORTED
   if ((png_ptr->transformations & PNG_ENCODE_ALPHA) != 0 &&
       (row_info->color_type & PNG_COLOR_MASK_ALPHA) != 0)
      png_do_encode_alpha(row_info, png_ptr->row_buf + 1, png_ptr);
#endif

#ifdef PNG_READ_SCALE_16_TO_8_SUPPORTED
   if ((png_ptr->transformations & PNG_SCALE_16_TO_8) != 0)
      png_do_scale_16_to_8(row_info, png_ptr->row_buf + 1);
#endif

#ifdef PNG_READ_STRIP_16_TO_8_SUPPORTED
   /* There is no harm in doing both of these because only one has any effect,
    * by putting the 'scale' option first if the app asks for scale (either by
    * calling the API or in a TRANSFORM flag) this is what happens.
    */
   if ((png_ptr->transformations & PNG_16_TO_8) != 0)
      png_do_chop(row_info, png_ptr->row_buf + 1);
#endif

#ifdef PNG_READ_QUANTIZE_SUPPORTED
   if ((png_ptr->transformations & PNG_QUANTIZE) != 0)
   {
      png_do_quantize(row_info, png_ptr->row_buf + 1,
          png_ptr->palette_lookup, png_ptr->quantize_index);

      if (row_info->rowbytes == 0)
         png_error(png_ptr, "png_do_quantize returned rowbytes=0");
   }
#endif /* READ_QUANTIZE */

#ifdef PNG_READ_EXPAND_16_SUPPORTED
   /* Do the expansion now, after all the arithmetic has been done.  Notice
    * that previous transformations can handle the PNG_EXPAND_16 flag if this
    * is efficient (particularly true in the case of gamma correction, where
    * better accuracy results faster!)
    */
   if ((png_ptr->transformations & PNG_EXPAND_16) != 0)
      png_do_expand_16(row_info, png_ptr->row_buf + 1);
#endif

#ifdef PNG_READ_GRAY_TO_RGB_SUPPORTED
   /* NOTE: moved here in 1.5.4 (from much later in this list.) */
   if ((png_ptr->transformations & PNG_GRAY_TO_RGB) != 0 &&
       (png_ptr->mode & PNG_BACKGROUND_IS_GRAY) != 0)
      png_do_gray_to_rgb(row_info, png_ptr->row_buf + 1);
#endif

#ifdef PNG_READ_INVERT_SUPPORTED
   if ((png_ptr->transformations & PNG_INVERT_MONO) != 0)
      png_do_invert(row_info, png_ptr->row_buf + 1);
#endif

#ifdef PNG_READ_INVERT_ALPHA_SUPPORTED
   if ((png_ptr->transformations & PNG_INVERT_ALPHA) != 0)
      png_do_read_invert_alpha(row_info, png_ptr->row_buf + 1);
#endif

#ifdef PNG_READ_SHIFT_SUPPORTED
   if ((png_ptr->transformations & PNG_SHIFT) != 0)
      png_do_unshift(row_info, png_ptr->row_buf + 1,
          &(png_ptr->shift));
#endif

#ifdef PNG_READ_PACK_SUPPORTED
   if ((png_ptr->transformations & PNG_PACK) != 0)
      png_do_unpack(row_info, png_ptr->row_buf + 1);
#endif

#ifdef PNG_READ_CHECK_FOR_INVALID_INDEX_SUPPORTED
   /* Added at libpng-1.5.10 */
   if (row_info->color_type == PNG_COLOR_TYPE_PALETTE &&
       png_ptr->num_palette_max >= 0)
      png_do_check_palette_indexes(png_ptr, row_info);
#endif

#ifdef PNG_READ_BGR_SUPPORTED
   if ((png_ptr->transformations & PNG_BGR) != 0)
      png_do_bgr(row_info, png_ptr->row_buf + 1);
#endif

#ifdef PNG_READ_PACKSWAP_SUPPORTED
   if ((png_ptr->transformations & PNG_PACKSWAP) != 0)
      png_do_packswap(row_info, png_ptr->row_buf + 1);
#endif

#ifdef PNG_READ_FILLER_SUPPORTED
   if ((png_ptr->transformations & PNG_FILLER) != 0)
      png_do_read_filler(row_info, png_ptr->row_buf + 1,
          (png_uint_32)png_ptr->filler, png_ptr->flags);
#endif

#ifdef PNG_READ_SWAP_ALPHA_SUPPORTED
   if ((png_ptr->transformations & PNG_SWAP_ALPHA) != 0)
      png_do_read_swap_alpha(row_info, png_ptr->row_buf + 1);
#endif

#ifdef PNG_READ_16BIT_SUPPORTED
#ifdef PNG_READ_SWAP_SUPPORTED
   if ((png_ptr->transformations & PNG_SWAP_BYTES) != 0)
      png_do_swap(row_info, png_ptr->row_buf + 1);
#endif
#endif

#ifdef PNG_READ_USER_TRANSFORM_SUPPORTED
   if ((png_ptr->transformations & PNG_USER_TRANSFORM) != 0)
   {
      if (png_ptr->read_user_transform_fn != NULL)
         (*(png_ptr->read_user_transform_fn)) /* User read transform function */
             (png_ptr,     /* png_ptr */
             row_info,     /* row_info: */
                /*  png_uint_32 width;       width of row */
                /*  size_t rowbytes;         number of bytes in row */
                /*  png_byte color_type;     color type of pixels */
                /*  png_byte bit_depth;      bit depth of samples */
                /*  png_byte channels;       number of channels (1-4) */
                /*  png_byte pixel_depth;    bits per pixel (depth*channels) */
             png_ptr->row_buf + 1);    /* start of pixel data for row */
#ifdef PNG_USER_TRANSFORM_PTR_SUPPORTED
      if (png_ptr->user_transform_depth != 0)
         row_info->bit_depth = png_ptr->user_transform_depth;

      if (png_ptr->user_transform_channels != 0)
         row_info->channels = png_ptr->user_transform_channels;
#endif
      row_info->pixel_depth = (png_byte)(row_info->bit_depth *
          row_info->channels);

      row_info->rowbytes = PNG_ROWBYTES(row_info->pixel_depth, row_info->width);
   }
#endif
}
```


#### 修复函数（修复后）

```c
void /* PRIVATE */
png_do_read_transformations(png_structrp png_ptr, png_row_infop row_info)
{
   png_debug(1, "in png_do_read_transformations");

   if (png_ptr->row_buf == NULL)
   {
      /* Prior to 1.5.4 this output row/pass where the NULL pointer is, but this
       * error is incredibly rare and incredibly easy to debug without this
       * information.
       */
      png_error(png_ptr, "NULL row buffer");
   }

   /* The following is debugging; prior to 1.5.4 the code was never compiled in;
    * in 1.5.4 PNG_FLAG_DETECT_UNINITIALIZED was added and the macro
    * PNG_WARN_UNINITIALIZED_ROW removed.  In 1.6 the new flag is set only for
    * all transformations, however in practice the ROW_INIT always gets done on
    * demand, if necessary.
    */
   if ((png_ptr->flags & PNG_FLAG_DETECT_UNINITIALIZED) != 0 &&
       (png_ptr->flags & PNG_FLAG_ROW_INIT) == 0)
   {
      /* Application has failed to call either png_read_start_image() or
       * png_read_update_info() after setting transforms that expand pixels.
       * This check added to libpng-1.2.19 (but not enabled until 1.5.4).
       */
      png_error(png_ptr, "Uninitialized row");
   }

#ifdef PNG_READ_EXPAND_SUPPORTED
   if ((png_ptr->transformations & PNG_EXPAND) != 0)
   {
      if (row_info->color_type == PNG_COLOR_TYPE_PALETTE)
      {
#ifdef PNG_ARM_NEON_INTRINSICS_AVAILABLE
         if ((png_ptr->num_trans > 0) && (png_ptr->bit_depth == 8))
         {
            if (png_ptr->riffled_palette == NULL)
            {
               /* Initialize the accelerated palette expansion. */
               png_ptr->riffled_palette =
                   (png_bytep)png_malloc(png_ptr, 256 * 4);
               png_riffle_palette_neon(png_ptr);
            }
         }
#endif
         png_do_expand_palette(png_ptr, row_info, png_ptr->row_buf + 1,
             png_ptr->palette, png_ptr->trans_alpha, png_ptr->num_trans);
      }

      else
      {
         if (png_ptr->num_trans != 0 &&
             (png_ptr->transformations & PNG_EXPAND_tRNS) != 0)
            png_do_expand(row_info, png_ptr->row_buf + 1,
                &(png_ptr->trans_color));

         else
            png_do_expand(row_info, png_ptr->row_buf + 1, NULL);
      }
   }
#endif

#ifdef PNG_READ_STRIP_ALPHA_SUPPORTED
   if ((png_ptr->transformations & PNG_STRIP_ALPHA) != 0 &&
       (png_ptr->transformations & PNG_COMPOSE) == 0 &&
       (row_info->color_type == PNG_COLOR_TYPE_RGB_ALPHA ||
       row_info->color_type == PNG_COLOR_TYPE_GRAY_ALPHA))
      png_do_strip_channel(row_info, png_ptr->row_buf + 1,
          0 /* at_start == false, because SWAP_ALPHA happens later */);
#endif

#ifdef PNG_READ_RGB_TO_GRAY_SUPPORTED
   if ((png_ptr->transformations & PNG_RGB_TO_GRAY) != 0)
   {
      int rgb_error =
          png_do_rgb_to_gray(png_ptr, row_info,
              png_ptr->row_buf + 1);

      if (rgb_error != 0)
      {
         png_ptr->rgb_to_gray_status=1;
         if ((png_ptr->transformations & PNG_RGB_TO_GRAY) ==
             PNG_RGB_TO_GRAY_WARN)
            png_warning(png_ptr, "png_do_rgb_to_gray found nongray pixel");

         if ((png_ptr->transformations & PNG_RGB_TO_GRAY) ==
             PNG_RGB_TO_GRAY_ERR)
            png_error(png_ptr, "png_do_rgb_to_gray found nongray pixel");
      }
   }
#endif

/* From Andreas Dilger e-mail to png-implement, 26 March 1998:
 *
 *   In most cases, the "simple transparency" should be done prior to doing
 *   gray-to-RGB, or you will have to test 3x as many bytes to check if a
 *   pixel is transparent.  You would also need to make sure that the
 *   transparency information is upgraded to RGB.
 *
 *   To summarize, the current flow is:
 *   - Gray + simple transparency -> compare 1 or 2 gray bytes and composite
 *                                   with background "in place" if transparent,
 *                                   convert to RGB if necessary
 *   - Gray + alpha -> composite with gray background and remove alpha bytes,
 *                                   convert to RGB if necessary
 *
 *   To support RGB backgrounds for gray images we need:
 *   - Gray + simple transparency -> convert to RGB + simple transparency,
 *                                   compare 3 or 6 bytes and composite with
 *                                   background "in place" if transparent
 *                                   (3x compare/pixel compared to doing
 *                                   composite with gray bkgrnd)
 *   - Gray + alpha -> convert to RGB + alpha, composite with background and
 *                                   remove alpha bytes (3x float
 *                                   operations/pixel compared with composite
 *                                   on gray background)
 *
 *  Greg's change will do this.  The reason it wasn't done before is for
 *  performance, as this increases the per-pixel operations.  If we would check
 *  in advance if the background was gray or RGB, and position the gray-to-RGB
 *  transform appropriately, then it would save a lot of work/time.
 */

#ifdef PNG_READ_GRAY_TO_RGB_SUPPORTED
   /* If gray -> RGB, do so now only if background is non-gray; else do later
    * for performance reasons
    */
   if ((png_ptr->transformations & PNG_GRAY_TO_RGB) != 0 &&
       (png_ptr->mode & PNG_BACKGROUND_IS_GRAY) == 0)
      png_do_gray_to_rgb(row_info, png_ptr->row_buf + 1);
#endif

#if defined(PNG_READ_BACKGROUND_SUPPORTED) ||\
   defined(PNG_READ_ALPHA_MODE_SUPPORTED)
   if ((png_ptr->transformations & PNG_COMPOSE) != 0)
      png_do_compose(row_info, png_ptr->row_buf + 1, png_ptr);
#endif

#ifdef PNG_READ_GAMMA_SUPPORTED
   if ((png_ptr->transformations & PNG_GAMMA) != 0 &&
#ifdef PNG_READ_RGB_TO_GRAY_SUPPORTED
      /* Because RGB_TO_GRAY does the gamma transform. */
      (png_ptr->transformations & PNG_RGB_TO_GRAY) == 0 &&
#endif
#if defined(PNG_READ_BACKGROUND_SUPPORTED) ||\
   defined(PNG_READ_ALPHA_MODE_SUPPORTED)
      /* Because PNG_COMPOSE does the gamma transform if there is something to
       * do (if there is an alpha channel or transparency.)
       */
       !((png_ptr->transformations & PNG_COMPOSE) != 0 &&
       ((png_ptr->num_trans != 0) ||
       (png_ptr->color_type & PNG_COLOR_MASK_ALPHA) != 0)) &&
#endif
      /* Because png_init_read_transformations transforms the palette, unless
       * RGB_TO_GRAY will do the transform.
       */
       (png_ptr->color_type != PNG_COLOR_TYPE_PALETTE))
      png_do_gamma(row_info, png_ptr->row_buf + 1, png_ptr);
#endif

#ifdef PNG_READ_STRIP_ALPHA_SUPPORTED
   if ((png_ptr->transformations & PNG_STRIP_ALPHA) != 0 &&
       (png_ptr->transformations & PNG_COMPOSE) != 0 &&
       (row_info->color_type == PNG_COLOR_TYPE_RGB_ALPHA ||
       row_info->color_type == PNG_COLOR_TYPE_GRAY_ALPHA))
      png_do_strip_channel(row_info, png_ptr->row_buf + 1,
          0 /* at_start == false, because SWAP_ALPHA happens later */);
#endif

#ifdef PNG_READ_ALPHA_MODE_SUPPORTED
   if ((png_ptr->transformations & PNG_ENCODE_ALPHA) != 0 &&
       (row_info->color_type & PNG_COLOR_MASK_ALPHA) != 0)
      png_do_encode_alpha(row_info, png_ptr->row_buf + 1, png_ptr);
#endif

#ifdef PNG_READ_SCALE_16_TO_8_SUPPORTED
   if ((png_ptr->transformations & PNG_SCALE_16_TO_8) != 0)
      png_do_scale_16_to_8(row_info, png_ptr->row_buf + 1);
#endif

#ifdef PNG_READ_STRIP_16_TO_8_SUPPORTED
   /* There is no harm in doing both of these because only one has any effect,
    * by putting the 'scale' option first if the app asks for scale (either by
    * calling the API or in a TRANSFORM flag) this is what happens.
    */
   if ((png_ptr->transformations & PNG_16_TO_8) != 0)
      png_do_chop(row_info, png_ptr->row_buf + 1);
#endif

#ifdef PNG_READ_QUANTIZE_SUPPORTED
   if ((png_ptr->transformations & PNG_QUANTIZE) != 0)
      png_do_quantize(row_info, png_ptr->row_buf + 1,
          png_ptr->palette_lookup, png_ptr->quantize_index);
#endif /* READ_QUANTIZE */

#ifdef PNG_READ_EXPAND_16_SUPPORTED
   /* Do the expansion now, after all the arithmetic has been done.  Notice
    * that previous transformations can handle the PNG_EXPAND_16 flag if this
    * is efficient (particularly true in the case of gamma correction, where
    * better accuracy results faster!)
    */
   if ((png_ptr->transformations & PNG_EXPAND_16) != 0)
      png_do_expand_16(row_info, png_ptr->row_buf + 1);
#endif

#ifdef PNG_READ_GRAY_TO_RGB_SUPPORTED
   /* NOTE: moved here in 1.5.4 (from much later in this list.) */
   if ((png_ptr->transformations & PNG_GRAY_TO_RGB) != 0 &&
       (png_ptr->mode & PNG_BACKGROUND_IS_GRAY) != 0)
      png_do_gray_to_rgb(row_info, png_ptr->row_buf + 1);
#endif

#ifdef PNG_READ_INVERT_SUPPORTED
   if ((png_ptr->transformations & PNG_INVERT_MONO) != 0)
      png_do_invert(row_info, png_ptr->row_buf + 1);
#endif

#ifdef PNG_READ_INVERT_ALPHA_SUPPORTED
   if ((png_ptr->transformations & PNG_INVERT_ALPHA) != 0)
      png_do_read_invert_alpha(row_info, png_ptr->row_buf + 1);
#endif

#ifdef PNG_READ_SHIFT_SUPPORTED
   if ((png_ptr->transformations & PNG_SHIFT) != 0)
      png_do_unshift(row_info, png_ptr->row_buf + 1,
          &(png_ptr->shift));
#endif

#ifdef PNG_READ_PACK_SUPPORTED
   if ((png_ptr->transformations & PNG_PACK) != 0)
      png_do_unpack(row_info, png_ptr->row_buf + 1);
#endif

#ifdef PNG_READ_CHECK_FOR_INVALID_INDEX_SUPPORTED
   /* Added at libpng-1.5.10 */
   if (row_info->color_type == PNG_COLOR_TYPE_PALETTE &&
       png_ptr->num_palette_max >= 0)
      png_do_check_palette_indexes(png_ptr, row_info);
#endif

#ifdef PNG_READ_BGR_SUPPORTED
   if ((png_ptr->transformations & PNG_BGR) != 0)
      png_do_bgr(row_info, png_ptr->row_buf + 1);
#endif

#ifdef PNG_READ_PACKSWAP_SUPPORTED
   if ((png_ptr->transformations & PNG_PACKSWAP) != 0)
      png_do_packswap(row_info, png_ptr->row_buf + 1);
#endif

#ifdef PNG_READ_FILLER_SUPPORTED
   if ((png_ptr->transformations & PNG_FILLER) != 0)
      png_do_read_filler(row_info, png_ptr->row_buf + 1,
          (png_uint_32)png_ptr->filler, png_ptr->flags);
#endif

#ifdef PNG_READ_SWAP_ALPHA_SUPPORTED
   if ((png_ptr->transformations & PNG_SWAP_ALPHA) != 0)
      png_do_read_swap_alpha(row_info, png_ptr->row_buf + 1);
#endif

#ifdef PNG_READ_16BIT_SUPPORTED
#ifdef PNG_READ_SWAP_SUPPORTED
   if ((png_ptr->transformations & PNG_SWAP_BYTES) != 0)
      png_do_swap(row_info, png_ptr->row_buf + 1);
#endif
#endif

#ifdef PNG_READ_USER_TRANSFORM_SUPPORTED
   if ((png_ptr->transformations & PNG_USER_TRANSFORM) != 0)
   {
      if (png_ptr->read_user_transform_fn != NULL)
         (*(png_ptr->read_user_transform_fn)) /* User read transform function */
             (png_ptr,     /* png_ptr */
             row_info,     /* row_info: */
                /*  png_uint_32 width;       width of row */
                /*  size_t rowbytes;         number of bytes in row */
                /*  png_byte color_type;     color type of pixels */
                /*  png_byte bit_depth;      bit depth of samples */
                /*  png_byte channels;       number of channels (1-4) */
                /*  png_byte pixel_depth;    bits per pixel (depth*channels) */
             png_ptr->row_buf + 1);    /* start of pixel data for row */
#ifdef PNG_USER_TRANSFORM_PTR_SUPPORTED
      if (png_ptr->user_transform_depth != 0)
         row_info->bit_depth = png_ptr->user_transform_depth;

      if (png_ptr->user_transform_channels != 0)
         row_info->channels = png_ptr->user_transform_channels;
#endif
      row_info->pixel_depth = (png_byte)(row_info->bit_depth *
          row_info->channels);

      row_info->rowbytes = PNG_ROWBYTES(row_info->pixel_depth, row_info->width);
   }
#endif
}
```


#### 关键变更行

```diff
-    {
- 
-       if (row_info->rowbytes == 0)
-          png_error(png_ptr, "png_do_quantize returned rowbytes=0");
-    }
```


---

### 3. `struct png_struct_def`

**文件**：`pngstruct.h`  |  **变更**：+0 / -2 行  |  ✅ 完整函数体（源文件已获取）

**Hunk 位置**：`@@ -421,7 +421,6 @@ struct png_struct_def`


#### 漏洞函数（修复前）

```c
struct png_struct_def
{
#ifdef PNG_SETJMP_SUPPORTED
   jmp_buf jmp_buf_local;     /* New name in 1.6.0 for jmp_buf in png_struct */
   png_longjmp_ptr longjmp_fn;/* setjmp non-local goto function. */
   jmp_buf *jmp_buf_ptr;      /* passed to longjmp_fn */
   size_t jmp_buf_size;       /* size of the above, if allocated */
#endif
   png_error_ptr error_fn;    /* function for printing errors and aborting */
#ifdef PNG_WARNINGS_SUPPORTED
   png_error_ptr warning_fn;  /* function for printing warnings */
#endif
   png_voidp error_ptr;       /* user supplied struct for error functions */
   png_rw_ptr write_data_fn;  /* function for writing output data */
   png_rw_ptr read_data_fn;   /* function for reading input data */
   png_voidp io_ptr;          /* ptr to application struct for I/O functions */

#ifdef PNG_READ_USER_TRANSFORM_SUPPORTED
   png_user_transform_ptr read_user_transform_fn; /* user read transform */
#endif

#ifdef PNG_WRITE_USER_TRANSFORM_SUPPORTED
   png_user_transform_ptr write_user_transform_fn; /* user write transform */
#endif

/* These were added in libpng-1.0.2 */
#ifdef PNG_USER_TRANSFORM_PTR_SUPPORTED
#if defined(PNG_READ_USER_TRANSFORM_SUPPORTED) || \
    defined(PNG_WRITE_USER_TRANSFORM_SUPPORTED)
   png_voidp user_transform_ptr; /* user supplied struct for user transform */
   png_byte user_transform_depth;    /* bit depth of user transformed pixels */
   png_byte user_transform_channels; /* channels in user transformed pixels */
#endif
#endif

   png_uint_32 mode;          /* tells us where we are in the PNG file */
   png_uint_32 flags;         /* flags indicating various things to libpng */
   png_uint_32 transformations; /* which transformations to perform */

   png_uint_32 zowner;        /* ID (chunk type) of zstream owner, 0 if none */
   z_stream    zstream;       /* decompression structure */

#ifdef PNG_WRITE_SUPPORTED
   png_compression_bufferp zbuffer_list; /* Created on demand during write */
   uInt                    zbuffer_size; /* size of the actual buffer */

   int zlib_level;            /* holds zlib compression level */
   int zlib_method;           /* holds zlib compression method */
   int zlib_window_bits;      /* holds zlib compression window bits */
   int zlib_mem_level;        /* holds zlib compression memory level */
   int zlib_strategy;         /* holds zlib compression strategy */
#endif
/* Added at libpng 1.5.4 */
#ifdef PNG_WRITE_CUSTOMIZE_ZTXT_COMPRESSION_SUPPORTED
   int zlib_text_level;            /* holds zlib compression level */
   int zlib_text_method;           /* holds zlib compression method */
   int zlib_text_window_bits;      /* holds zlib compression window bits */
   int zlib_text_mem_level;        /* holds zlib compression memory level */
   int zlib_text_strategy;         /* holds zlib compression strategy */
#endif
/* End of material added at libpng 1.5.4 */
/* Added at libpng 1.6.0 */
#ifdef PNG_WRITE_SUPPORTED
   int zlib_set_level;        /* Actual values set into the zstream on write */
   int zlib_set_method;
   int zlib_set_window_bits;
   int zlib_set_mem_level;
   int zlib_set_strategy;
#endif

   png_uint_32 chunks; /* PNG_CF_ for every chunk read or (NYI) written */
#  define png_has_chunk(png_ptr, cHNK)\
      png_file_has_chunk(png_ptr, PNG_INDEX_ ## cHNK)
      /* Convenience accessor - use this to check for a known chunk by name */

   png_uint_32 width;         /* width of image in pixels */
   png_uint_32 height;        /* height of image in pixels */
   png_uint_32 num_rows;      /* number of rows in current pass */
   png_uint_32 usr_width;     /* width of row at start of write */
   size_t rowbytes;           /* size of row in bytes */
   png_uint_32 iwidth;        /* width of current interlaced row in pixels */
   png_uint_32 row_number;    /* current row in interlace pass */
   png_uint_32 chunk_name;    /* PNG_CHUNK() id of current chunk */
   png_bytep prev_row;        /* buffer to save previous (unfiltered) row.
                               * While reading this is a pointer into
                               * big_prev_row; while writing it is separately
                               * allocated if needed.
                               */
   png_bytep row_buf;         /* buffer to save current (unfiltered) row.
                               * While reading, this is a pointer into
                               * big_row_buf; while writing it is separately
                               * allocated.
                               */
#ifdef PNG_WRITE_FILTER_SUPPORTED
   png_bytep try_row;    /* buffer to save trial row when filtering */
   png_bytep tst_row;    /* buffer to save best trial row when filtering */
#endif
   size_t info_rowbytes;      /* Added in 1.5.4: cache of updated row bytes */

   png_uint_32 idat_size;     /* current IDAT size for read */
   png_uint_32 crc;           /* current chunk CRC value */
   png_colorp palette;        /* palette from the input file */
   png_uint_16 num_palette;   /* number of color entries in palette */

/* Added at libpng-1.5.10 */
#ifdef PNG_CHECK_FOR_INVALID_INDEX_SUPPORTED
   int num_palette_max;       /* maximum palette index found in IDAT */
#endif

   png_uint_16 num_trans;     /* number of transparency values */
   png_byte compression;      /* file compression type (always 0) */
   png_byte filter;           /* file filter type (always 0) */
   png_byte interlaced;       /* PNG_INTERLACE_NONE, PNG_INTERLACE_ADAM7 */
   png_byte pass;             /* current interlace pass (0 - 6) */
   png_byte do_filter;        /* row filter flags (see PNG_FILTER_ in png.h ) */
   png_byte color_type;       /* color type of file */
   png_byte bit_depth;        /* bit depth of file */
   png_byte usr_bit_depth;    /* bit depth of users row: write only */
   png_byte pixel_depth;      /* number of bits per pixel */
   png_byte channels;         /* number of channels in file */
#ifdef PNG_WRITE_SUPPORTED
   png_byte usr_channels;     /* channels at start of write: write only */
#endif
   png_byte sig_bytes;        /* magic bytes read/written from start of file */
   png_byte maximum_pixel_depth;
                              /* pixel depth used for the row buffers */
   png_byte transformed_pixel_depth;
                              /* pixel depth after read/write transforms */
#if ZLIB_VERNUM >= 0x1240
   png_byte zstream_start;    /* at start of an input zlib stream */
#endif /* Zlib >= 1.2.4 */
#if defined(PNG_READ_FILLER_SUPPORTED) || defined(PNG_WRITE_FILLER_SUPPORTED)
   png_uint_16 filler;           /* filler bytes for pixel expansion */
#endif

#if defined(PNG_bKGD_SUPPORTED) || defined(PNG_READ_BACKGROUND_SUPPORTED) ||\
   defined(PNG_READ_ALPHA_MODE_SUPPORTED)
   png_byte background_gamma_type;
   png_fixed_point background_gamma;
   png_color_16 background;   /* background color in screen gamma space */
#ifdef PNG_READ_GAMMA_SUPPORTED
   png_color_16 background_1; /* background normalized to gamma 1.0 */
#endif
#endif /* bKGD */

#ifdef PNG_WRITE_FLUSH_SUPPORTED
   png_flush_ptr output_flush_fn; /* Function for flushing output */
   png_uint_32 flush_dist;    /* how many rows apart to flush, 0 - no flush */
   png_uint_32 flush_rows;    /* number of rows written since last flush */
#endif

#ifdef PNG_READ_RGB_TO_GRAY_SUPPORTED
   png_xy          chromaticities; /* From mDVC, cICP, [iCCP], sRGB or cHRM */
#endif

#ifdef PNG_READ_GAMMA_SUPPORTED
   int gamma_shift;      /* number of "insignificant" bits in 16-bit gamma */
   png_fixed_point screen_gamma; /* screen gamma value (display exponent) */
   png_fixed_point file_gamma;   /* file gamma value (encoding exponent) */
   png_fixed_point chunk_gamma;  /* from cICP, iCCP, sRGB or gAMA */
   png_fixed_point default_gamma;/* from png_set_alpha_mode */

   png_bytep gamma_table;     /* gamma table for 8-bit depth files */
   png_uint_16pp gamma_16_table; /* gamma table for 16-bit depth files */
#if defined(PNG_READ_BACKGROUND_SUPPORTED) || \
   defined(PNG_READ_ALPHA_MODE_SUPPORTED) || \
   defined(PNG_READ_RGB_TO_GRAY_SUPPORTED)
   png_bytep gamma_from_1;    /* converts from 1.0 to screen */
   png_bytep gamma_to_1;      /* converts from file to 1.0 */
   png_uint_16pp gamma_16_from_1; /* converts from 1.0 to screen */
   png_uint_16pp gamma_16_to_1; /* converts from file to 1.0 */
#endif /* READ_BACKGROUND || READ_ALPHA_MODE || RGB_TO_GRAY */
#endif /* READ_GAMMA */

#if defined(PNG_READ_GAMMA_SUPPORTED) || defined(PNG_sBIT_SUPPORTED)
   png_color_8 sig_bit;       /* significant bits in each available channel */
#endif

#if defined(PNG_READ_SHIFT_SUPPORTED) || defined(PNG_WRITE_SHIFT_SUPPORTED)
   png_color_8 shift;         /* shift for significant bit transformation */
#endif

#if defined(PNG_tRNS_SUPPORTED) || defined(PNG_READ_BACKGROUND_SUPPORTED) \
 || defined(PNG_READ_EXPAND_SUPPORTED) || defined(PNG_READ_BACKGROUND_SUPPORTED)
   png_bytep trans_alpha;           /* alpha values for paletted files */
   png_color_16 trans_color;  /* transparent color for non-paletted files */
#endif

   png_read_status_ptr read_row_fn;   /* called after each row is decoded */
   png_write_status_ptr write_row_fn; /* called after each row is encoded */
#ifdef PNG_PROGRESSIVE_READ_SUPPORTED
   png_progressive_info_ptr info_fn; /* called after header data fully read */
   png_progressive_row_ptr row_fn;   /* called after a prog. row is decoded */
   png_progressive_end_ptr end_fn;   /* called after image is complete */
   png_bytep save_buffer_ptr;        /* current location in save_buffer */
   png_bytep save_buffer;            /* buffer for previously read data */
   png_bytep current_buffer_ptr;     /* current location in current_buffer */
   png_bytep current_buffer;         /* buffer for recently used data */
   png_uint_32 push_length;          /* size of current input chunk */
   png_uint_32 skip_length;          /* bytes to skip in input data */
   size_t save_buffer_size;          /* amount of data now in save_buffer */
   size_t save_buffer_max;           /* total size of save_buffer */
   size_t buffer_size;               /* total amount of available input data */
   size_t current_buffer_size;       /* amount of data now in current_buffer */
   int process_mode;                 /* what push library is currently doing */
   int cur_palette;                  /* current push library palette index */
#endif /* PROGRESSIVE_READ */

#ifdef PNG_READ_QUANTIZE_SUPPORTED
   png_bytep palette_lookup; /* lookup table for quantizing */
   png_bytep quantize_index; /* index translation for palette files */
#endif

/* Options */
#ifdef PNG_SET_OPTION_SUPPORTED
   png_uint_32 options;           /* On/off state (up to 16 options) */
#endif

#if PNG_LIBPNG_VER < 10700
/* To do: remove this from libpng-1.7 */
#ifdef PNG_TIME_RFC1123_SUPPORTED
   char time_buffer[29]; /* String to hold RFC 1123 time text */
#endif /* TIME_RFC1123 */
#endif /* LIBPNG_VER < 10700 */

/* New members added in libpng-1.0.6 */

   png_uint_32 free_me;    /* flags items libpng is responsible for freeing */

#ifdef PNG_USER_CHUNKS_SUPPORTED
   png_voidp user_chunk_ptr;
#ifdef PNG_READ_USER_CHUNKS_SUPPORTED
   png_user_chunk_ptr read_user_chunk_fn; /* user read chunk handler */
#endif /* READ_USER_CHUNKS */
#endif /* USER_CHUNKS */

#ifdef PNG_SET_UNKNOWN_CHUNKS_SUPPORTED
   int          unknown_default; /* As PNG_HANDLE_* */
   unsigned int num_chunk_list;  /* Number of entries in the list */
   png_bytep    chunk_list;      /* List of png_byte[5]; the textual chunk name
                                  * followed by a PNG_HANDLE_* byte */
#endif

/* New members added in libpng-1.0.3 */
#ifdef PNG_READ_RGB_TO_GRAY_SUPPORTED
   png_byte rgb_to_gray_status;
   /* Added in libpng 1.5.5 to record setting of coefficients: */
   png_byte rgb_to_gray_coefficients_set;
   /* These were changed from png_byte in libpng-1.0.6 */
   png_uint_16 rgb_to_gray_red_coeff;
   png_uint_16 rgb_to_gray_green_coeff;
   /* deleted in 1.5.5: rgb_to_gray_blue_coeff; */
#endif

/* New member added in libpng-1.6.36 */
#if defined(PNG_READ_EXPAND_SUPPORTED) && \
    (defined(PNG_ARM_NEON_IMPLEMENTATION) || \
     defined(PNG_RISCV_RVV_IMPLEMENTATION))
   png_bytep riffled_palette; /* buffer for accelerated palette expansion */
#endif

/* New member added in libpng-1.0.4 (renamed in 1.0.9) */
#if defined(PNG_MNG_FEATURES_SUPPORTED)
/* Changed from png_byte to png_uint_32 at version 1.2.0 */
   png_uint_32 mng_features_permitted;
#endif

/* New member added in libpng-1.0.9, ifdef'ed out in 1.0.12, enabled in 1.2.0 */
#ifdef PNG_MNG_FEATURES_SUPPORTED
   png_byte filter_type;
#endif

/* New members added in libpng-1.2.0 */

/* New members added in libpng-1.0.2 but first enabled by default in 1.2.0 */
#ifdef PNG_USER_MEM_SUPPORTED
   png_voidp mem_ptr;             /* user supplied struct for mem functions */
   png_malloc_ptr malloc_fn;      /* function for allocating memory */
   png_free_ptr free_fn;          /* function for freeing memory */
#endif

/* New member added in libpng-1.0.13 and 1.2.0 */
   png_bytep big_row_buf;         /* buffer to save current (unfiltered) row */

#ifdef PNG_READ_QUANTIZE_SUPPORTED
/* The following three members were added at version 1.0.14 and 1.2.4 */
   png_bytep quantize_sort;          /* working sort array */
   png_bytep index_to_palette;       /* where the original index currently is
                                        in the palette */
   png_bytep palette_to_index;       /* which original index points to this
- 
                                         palette color */
#endif

/* New members added in libpng-1.0.16 and 1.2.6 */
   png_byte compression_type;

#ifdef PNG_USER_LIMITS_SUPPORTED
   png_uint_32 user_width_max;
   png_uint_32 user_height_max;

   /* Added in libpng-1.4.0: Total number of sPLT, text, and unknown
    * chunks that can be stored (0 means unlimited).
    */
   png_uint_32 user_chunk_cache_max;

   /* Total memory that a zTXt, sPLT, iTXt, iCCP, or unknown chunk
    * can occupy when decompressed.  0 means unlimited.
    */
   png_alloc_size_t user_chunk_malloc_max;
#endif

/* New member added in libpng-1.0.25 and 1.2.17 */
#ifdef PNG_READ_UNKNOWN_CHUNKS_SUPPORTED
   /* Temporary storage for unknown chunk that the library doesn't recognize,
    * used while reading the chunk.
    */
   png_unknown_chunk unknown_chunk;
#endif

/* New member added in libpng-1.2.26 */
   size_t old_big_row_buf_size;

#ifdef PNG_READ_SUPPORTED
/* New member added in libpng-1.2.30 */
  png_bytep        read_buffer;      /* buffer for reading chunk data */
  png_alloc_size_t read_buffer_size; /* current size of the buffer */
#endif
#ifdef PNG_SEQUENTIAL_READ_SUPPORTED
  uInt             IDAT_read_size;   /* limit on read buffer size for IDAT */
#endif

#ifdef PNG_IO_STATE_SUPPORTED
/* New member added in libpng-1.4.0 */
   png_uint_32 io_state;
#endif

/* New member added in libpng-1.5.6 */
   png_bytep big_prev_row;

/* New member added in libpng-1.5.7 */
   void (*read_filter[PNG_FILTER_VALUE_LAST-1])(png_row_infop row_info,
      png_bytep row, png_const_bytep prev_row);
};
```


#### 修复函数（修复后）

```c
struct png_struct_def
{
#ifdef PNG_SETJMP_SUPPORTED
   jmp_buf jmp_buf_local;     /* New name in 1.6.0 for jmp_buf in png_struct */
   png_longjmp_ptr longjmp_fn;/* setjmp non-local goto function. */
   jmp_buf *jmp_buf_ptr;      /* passed to longjmp_fn */
   size_t jmp_buf_size;       /* size of the above, if allocated */
#endif
   png_error_ptr error_fn;    /* function for printing errors and aborting */
#ifdef PNG_WARNINGS_SUPPORTED
   png_error_ptr warning_fn;  /* function for printing warnings */
#endif
   png_voidp error_ptr;       /* user supplied struct for error functions */
   png_rw_ptr write_data_fn;  /* function for writing output data */
   png_rw_ptr read_data_fn;   /* function for reading input data */
   png_voidp io_ptr;          /* ptr to application struct for I/O functions */

#ifdef PNG_READ_USER_TRANSFORM_SUPPORTED
   png_user_transform_ptr read_user_transform_fn; /* user read transform */
#endif

#ifdef PNG_WRITE_USER_TRANSFORM_SUPPORTED
   png_user_transform_ptr write_user_transform_fn; /* user write transform */
#endif

/* These were added in libpng-1.0.2 */
#ifdef PNG_USER_TRANSFORM_PTR_SUPPORTED
#if defined(PNG_READ_USER_TRANSFORM_SUPPORTED) || \
    defined(PNG_WRITE_USER_TRANSFORM_SUPPORTED)
   png_voidp user_transform_ptr; /* user supplied struct for user transform */
   png_byte user_transform_depth;    /* bit depth of user transformed pixels */
   png_byte user_transform_channels; /* channels in user transformed pixels */
#endif
#endif

   png_uint_32 mode;          /* tells us where we are in the PNG file */
   png_uint_32 flags;         /* flags indicating various things to libpng */
   png_uint_32 transformations; /* which transformations to perform */

   png_uint_32 zowner;        /* ID (chunk type) of zstream owner, 0 if none */
   z_stream    zstream;       /* decompression structure */

#ifdef PNG_WRITE_SUPPORTED
   png_compression_bufferp zbuffer_list; /* Created on demand during write */
   uInt                    zbuffer_size; /* size of the actual buffer */

   int zlib_level;            /* holds zlib compression level */
   int zlib_method;           /* holds zlib compression method */
   int zlib_window_bits;      /* holds zlib compression window bits */
   int zlib_mem_level;        /* holds zlib compression memory level */
   int zlib_strategy;         /* holds zlib compression strategy */
#endif
/* Added at libpng 1.5.4 */
#ifdef PNG_WRITE_CUSTOMIZE_ZTXT_COMPRESSION_SUPPORTED
   int zlib_text_level;            /* holds zlib compression level */
   int zlib_text_method;           /* holds zlib compression method */
   int zlib_text_window_bits;      /* holds zlib compression window bits */
   int zlib_text_mem_level;        /* holds zlib compression memory level */
   int zlib_text_strategy;         /* holds zlib compression strategy */
#endif
/* End of material added at libpng 1.5.4 */
/* Added at libpng 1.6.0 */
#ifdef PNG_WRITE_SUPPORTED
   int zlib_set_level;        /* Actual values set into the zstream on write */
   int zlib_set_method;
   int zlib_set_window_bits;
   int zlib_set_mem_level;
   int zlib_set_strategy;
#endif

   png_uint_32 chunks; /* PNG_CF_ for every chunk read or (NYI) written */
#  define png_has_chunk(png_ptr, cHNK)\
      png_file_has_chunk(png_ptr, PNG_INDEX_ ## cHNK)
      /* Convenience accessor - use this to check for a known chunk by name */

   png_uint_32 width;         /* width of image in pixels */
   png_uint_32 height;        /* height of image in pixels */
   png_uint_32 num_rows;      /* number of rows in current pass */
   png_uint_32 usr_width;     /* width of row at start of write */
   size_t rowbytes;           /* size of row in bytes */
   png_uint_32 iwidth;        /* width of current interlaced row in pixels */
   png_uint_32 row_number;    /* current row in interlace pass */
   png_uint_32 chunk_name;    /* PNG_CHUNK() id of current chunk */
   png_bytep prev_row;        /* buffer to save previous (unfiltered) row.
                               * While reading this is a pointer into
                               * big_prev_row; while writing it is separately
                               * allocated if needed.
                               */
   png_bytep row_buf;         /* buffer to save current (unfiltered) row.
                               * While reading, this is a pointer into
                               * big_row_buf; while writing it is separately
                               * allocated.
                               */
#ifdef PNG_WRITE_FILTER_SUPPORTED
   png_bytep try_row;    /* buffer to save trial row when filtering */
   png_bytep tst_row;    /* buffer to save best trial row when filtering */
#endif
   size_t info_rowbytes;      /* Added in 1.5.4: cache of updated row bytes */

   png_uint_32 idat_size;     /* current IDAT size for read */
   png_uint_32 crc;           /* current chunk CRC value */
   png_colorp palette;        /* palette from the input file */
   png_uint_16 num_palette;   /* number of color entries in palette */

/* Added at libpng-1.5.10 */
#ifdef PNG_CHECK_FOR_INVALID_INDEX_SUPPORTED
   int num_palette_max;       /* maximum palette index found in IDAT */
#endif

   png_uint_16 num_trans;     /* number of transparency values */
   png_byte compression;      /* file compression type (always 0) */
   png_byte filter;           /* file filter type (always 0) */
   png_byte interlaced;       /* PNG_INTERLACE_NONE, PNG_INTERLACE_ADAM7 */
   png_byte pass;             /* current interlace pass (0 - 6) */
   png_byte do_filter;        /* row filter flags (see PNG_FILTER_ in png.h ) */
   png_byte color_type;       /* color type of file */
   png_byte bit_depth;        /* bit depth of file */
   png_byte usr_bit_depth;    /* bit depth of users row: write only */
   png_byte pixel_depth;      /* number of bits per pixel */
   png_byte channels;         /* number of channels in file */
#ifdef PNG_WRITE_SUPPORTED
   png_byte usr_channels;     /* channels at start of write: write only */
#endif
   png_byte sig_bytes;        /* magic bytes read/written from start of file */
   png_byte maximum_pixel_depth;
                              /* pixel depth used for the row buffers */
   png_byte transformed_pixel_depth;
                              /* pixel depth after read/write transforms */
#if ZLIB_VERNUM >= 0x1240
   png_byte zstream_start;    /* at start of an input zlib stream */
#endif /* Zlib >= 1.2.4 */
#if defined(PNG_READ_FILLER_SUPPORTED) || defined(PNG_WRITE_FILLER_SUPPORTED)
   png_uint_16 filler;           /* filler bytes for pixel expansion */
#endif

#if defined(PNG_bKGD_SUPPORTED) || defined(PNG_READ_BACKGROUND_SUPPORTED) ||\
   defined(PNG_READ_ALPHA_MODE_SUPPORTED)
   png_byte background_gamma_type;
   png_fixed_point background_gamma;
   png_color_16 background;   /* background color in screen gamma space */
#ifdef PNG_READ_GAMMA_SUPPORTED
   png_color_16 background_1; /* background normalized to gamma 1.0 */
#endif
#endif /* bKGD */

#ifdef PNG_WRITE_FLUSH_SUPPORTED
   png_flush_ptr output_flush_fn; /* Function for flushing output */
   png_uint_32 flush_dist;    /* how many rows apart to flush, 0 - no flush */
   png_uint_32 flush_rows;    /* number of rows written since last flush */
#endif

#ifdef PNG_READ_RGB_TO_GRAY_SUPPORTED
   png_xy          chromaticities; /* From mDVC, cICP, [iCCP], sRGB or cHRM */
#endif

#ifdef PNG_READ_GAMMA_SUPPORTED
   int gamma_shift;      /* number of "insignificant" bits in 16-bit gamma */
   png_fixed_point screen_gamma; /* screen gamma value (display exponent) */
   png_fixed_point file_gamma;   /* file gamma value (encoding exponent) */
   png_fixed_point chunk_gamma;  /* from cICP, iCCP, sRGB or gAMA */
   png_fixed_point default_gamma;/* from png_set_alpha_mode */

   png_bytep gamma_table;     /* gamma table for 8-bit depth files */
   png_uint_16pp gamma_16_table; /* gamma table for 16-bit depth files */
#if defined(PNG_READ_BACKGROUND_SUPPORTED) || \
   defined(PNG_READ_ALPHA_MODE_SUPPORTED) || \
   defined(PNG_READ_RGB_TO_GRAY_SUPPORTED)
   png_bytep gamma_from_1;    /* converts from 1.0 to screen */
   png_bytep gamma_to_1;      /* converts from file to 1.0 */
   png_uint_16pp gamma_16_from_1; /* converts from 1.0 to screen */
   png_uint_16pp gamma_16_to_1; /* converts from file to 1.0 */
#endif /* READ_BACKGROUND || READ_ALPHA_MODE || RGB_TO_GRAY */
#endif /* READ_GAMMA */

#if defined(PNG_READ_GAMMA_SUPPORTED) || defined(PNG_sBIT_SUPPORTED)
   png_color_8 sig_bit;       /* significant bits in each available channel */
#endif

#if defined(PNG_READ_SHIFT_SUPPORTED) || defined(PNG_WRITE_SHIFT_SUPPORTED)
   png_color_8 shift;         /* shift for significant bit transformation */
#endif

#if defined(PNG_tRNS_SUPPORTED) || defined(PNG_READ_BACKGROUND_SUPPORTED) \
 || defined(PNG_READ_EXPAND_SUPPORTED) || defined(PNG_READ_BACKGROUND_SUPPORTED)
   png_bytep trans_alpha;           /* alpha values for paletted files */
   png_color_16 trans_color;  /* transparent color for non-paletted files */
#endif

   png_read_status_ptr read_row_fn;   /* called after each row is decoded */
   png_write_status_ptr write_row_fn; /* called after each row is encoded */
#ifdef PNG_PROGRESSIVE_READ_SUPPORTED
   png_progressive_info_ptr info_fn; /* called after header data fully read */
   png_progressive_row_ptr row_fn;   /* called after a prog. row is decoded */
   png_progressive_end_ptr end_fn;   /* called after image is complete */
   png_bytep save_buffer_ptr;        /* current location in save_buffer */
   png_bytep save_buffer;            /* buffer for previously read data */
   png_bytep current_buffer_ptr;     /* current location in current_buffer */
   png_bytep current_buffer;         /* buffer for recently used data */
   png_uint_32 push_length;          /* size of current input chunk */
   png_uint_32 skip_length;          /* bytes to skip in input data */
   size_t save_buffer_size;          /* amount of data now in save_buffer */
   size_t save_buffer_max;           /* total size of save_buffer */
   size_t buffer_size;               /* total amount of available input data */
   size_t current_buffer_size;       /* amount of data now in current_buffer */
   int process_mode;                 /* what push library is currently doing */
   int cur_palette;                  /* current push library palette index */
#endif /* PROGRESSIVE_READ */

#ifdef PNG_READ_QUANTIZE_SUPPORTED
   png_bytep palette_lookup; /* lookup table for quantizing */
   png_bytep quantize_index; /* index translation for palette files */
#endif

/* Options */
#ifdef PNG_SET_OPTION_SUPPORTED
   png_uint_32 options;           /* On/off state (up to 16 options) */
#endif

#if PNG_LIBPNG_VER < 10700
/* To do: remove this from libpng-1.7 */
#ifdef PNG_TIME_RFC1123_SUPPORTED
   char time_buffer[29]; /* String to hold RFC 1123 time text */
#endif /* TIME_RFC1123 */
#endif /* LIBPNG_VER < 10700 */

/* New members added in libpng-1.0.6 */

   png_uint_32 free_me;    /* flags items libpng is responsible for freeing */

#ifdef PNG_USER_CHUNKS_SUPPORTED
   png_voidp user_chunk_ptr;
#ifdef PNG_READ_USER_CHUNKS_SUPPORTED
   png_user_chunk_ptr read_user_chunk_fn; /* user read chunk handler */
#endif /* READ_USER_CHUNKS */
#endif /* USER_CHUNKS */

#ifdef PNG_SET_UNKNOWN_CHUNKS_SUPPORTED
   int          unknown_default; /* As PNG_HANDLE_* */
   unsigned int num_chunk_list;  /* Number of entries in the list */
   png_bytep    chunk_list;      /* List of png_byte[5]; the textual chunk name
                                  * followed by a PNG_HANDLE_* byte */
#endif

/* New members added in libpng-1.0.3 */
#ifdef PNG_READ_RGB_TO_GRAY_SUPPORTED
   png_byte rgb_to_gray_status;
   /* Added in libpng 1.5.5 to record setting of coefficients: */
   png_byte rgb_to_gray_coefficients_set;
   /* These were changed from png_byte in libpng-1.0.6 */
   png_uint_16 rgb_to_gray_red_coeff;
   png_uint_16 rgb_to_gray_green_coeff;
   /* deleted in 1.5.5: rgb_to_gray_blue_coeff; */
#endif

/* New member added in libpng-1.6.36 */
#if defined(PNG_READ_EXPAND_SUPPORTED) && \
    (defined(PNG_ARM_NEON_IMPLEMENTATION) || \
     defined(PNG_RISCV_RVV_IMPLEMENTATION))
   png_bytep riffled_palette; /* buffer for accelerated palette expansion */
#endif

/* New member added in libpng-1.0.4 (renamed in 1.0.9) */
#if defined(PNG_MNG_FEATURES_SUPPORTED)
/* Changed from png_byte to png_uint_32 at version 1.2.0 */
   png_uint_32 mng_features_permitted;
#endif

/* New member added in libpng-1.0.9, ifdef'ed out in 1.0.12, enabled in 1.2.0 */
#ifdef PNG_MNG_FEATURES_SUPPORTED
   png_byte filter_type;
#endif

/* New members added in libpng-1.2.0 */

/* New members added in libpng-1.0.2 but first enabled by default in 1.2.0 */
#ifdef PNG_USER_MEM_SUPPORTED
   png_voidp mem_ptr;             /* user supplied struct for mem functions */
   png_malloc_ptr malloc_fn;      /* function for allocating memory */
   png_free_ptr free_fn;          /* function for freeing memory */
#endif

/* New member added in libpng-1.0.13 and 1.2.0 */
   png_bytep big_row_buf;         /* buffer to save current (unfiltered) row */

#ifdef PNG_READ_QUANTIZE_SUPPORTED
/* The following three members were added at version 1.0.14 and 1.2.4 */
   png_bytep index_to_palette;       /* where the original index currently is
                                        in the palette */
   png_bytep palette_to_index;       /* which original index points to this
                                         palette color */
#endif

/* New members added in libpng-1.0.16 and 1.2.6 */
   png_byte compression_type;

#ifdef PNG_USER_LIMITS_SUPPORTED
   png_uint_32 user_width_max;
   png_uint_32 user_height_max;

   /* Added in libpng-1.4.0: Total number of sPLT, text, and unknown
    * chunks that can be stored (0 means unlimited).
    */
   png_uint_32 user_chunk_cache_max;

   /* Total memory that a zTXt, sPLT, iTXt, iCCP, or unknown chunk
    * can occupy when decompressed.  0 means unlimited.
    */
   png_alloc_size_t user_chunk_malloc_max;
#endif

/* New member added in libpng-1.0.25 and 1.2.17 */
#ifdef PNG_READ_UNKNOWN_CHUNKS_SUPPORTED
   /* Temporary storage for unknown chunk that the library doesn't recognize,
    * used while reading the chunk.
    */
   png_unknown_chunk unknown_chunk;
#endif

/* New member added in libpng-1.2.26 */
   size_t old_big_row_buf_size;

#ifdef PNG_READ_SUPPORTED
/* New member added in libpng-1.2.30 */
  png_bytep        read_buffer;      /* buffer for reading chunk data */
  png_alloc_size_t read_buffer_size; /* current size of the buffer */
#endif
#ifdef PNG_SEQUENTIAL_READ_SUPPORTED
  uInt             IDAT_read_size;   /* limit on read buffer size for IDAT */
#endif

#ifdef PNG_IO_STATE_SUPPORTED
/* New member added in libpng-1.4.0 */
   png_uint_32 io_state;
#endif

/* New member added in libpng-1.5.6 */
   png_bytep big_prev_row;

/* New member added in libpng-1.5.7 */
   void (*read_filter[PNG_FILTER_VALUE_LAST-1])(png_row_infop row_info,
      png_bytep row, png_const_bytep prev_row);
};
```


#### 关键变更行

```diff
-    png_bytep quantize_sort;          /* working sort array */
- - 
```


---

<a id="cve202539902"></a>

## CVE-2025-39902  ·  kernel_linux_5.10  ·  无

**参考链接**：<https://gitcode.com/openharmony/kernel_linux_5.10/commit/d7d744b905106891437463136db0a50353808185>

**标题**：mm/slub: avoid accessing metadata when pointer is invalid in

**漏洞描述**：

> stable inclusion
> from stable-v5.10.243
> commit f66012909e7bf383fcdc5850709ed5716073fdc4
> category: bugfix
> issue: #8063
> CVE: CVE-2025-39902
> ---------------------------------------
> [ Upstream commit b4efccec8d06ceb10a7d34d7b1c449c569d53770 ]
> object_err() reports details of an object for further debugging, such as
> the freelist pointer, redzone, etc. However, if the pointer is invalid,
> attempting to access object metadata can lead to a crash since it does
> not point to a valid object.


共涉及 **1** 个函数／代码区域：

### 1. `void object_err(struct kmem_cache *s, struct page *page,`

**文件**：`mm/slub.c`  |  **变更**：+6 / -1 行  |  ✅ 完整函数体（源文件已获取）

**Hunk 位置**：`@@ -729,7 +729,12 @@ void object_err(struct kmem_cache *s, struct page *page,`


#### 漏洞函数（修复前）

```c
void object_err(struct kmem_cache *s, struct page *page,
			u8 *object, char *reason)
{
	slab_bug(s, "%s", reason);
	print_trailer(s, page, object);
}
```


#### 修复函数（修复后）

```c
void object_err(struct kmem_cache *s, struct page *page,
			u8 *object, char *reason)
{
	slab_bug(s, "%s", reason);
	if (!object || !check_valid_pointer(s, page, object)) {
		print_page_info(page);
		pr_err("Invalid pointer 0x%p\n", object);
	} else {
		print_trailer(s, page, object);
	}
}
```


#### 关键变更行

```diff
- 	print_trailer(s, page, object);
+ 	if (!object || !check_valid_pointer(s, page, object)) {
+ 		print_page_info(page);
+ 		pr_err("Invalid pointer 0x%p\n", object);
+ 	} else {
+ 		print_trailer(s, page, object);
+ 	}
```


---

<a id="cve202539756"></a>

## CVE-2025-39756  ·  kernel_linux_5.10  ·  无

**参考链接**：<https://gitcode.com/openharmony/kernel_linux_5.10/commit/7c128ed092c50086ca467989d69b2e26ba0f155e>

**标题**：fs: Prevent file descriptor table allocations exceeding

**漏洞描述**：

> stable inclusion
> from stable-v5.10.241
> commit f95638a8f22eba307dceddf5aef9ae2326bbcf98
> category: bugfix
> issue: #8070
> CVE: CVE-2025-39756
> ---------------------------------------
> commit 04a2c4b4511d186b0fce685da21085a5d4acd370 upstream.
> When sysctl_nr_open is set to a very high value (for example, 1073741816
> as set by systemd), processes attempting to use file descriptors near
> the limit can trigger massive memory allocation attempts that exceed
> INT_MAX, resulting in a WARNING in mm/slub.c:


共涉及 **1** 个函数／代码区域：

### 1. `static struct fdtable * alloc_fdtable(unsigned int nr)`

**文件**：`fs/file.c`  |  **变更**：+15 / -0 行  |  ✅ 完整函数体（源文件已获取）

**Hunk 位置**：`@@ -129,6 +129,21 @@ static struct fdtable * alloc_fdtable(unsigned int nr)`


#### 漏洞函数（修复前）

```c
static struct fdtable * alloc_fdtable(unsigned int nr)
{
	struct fdtable *fdt;
	void *data;

	/*
	 * Figure out how many fds we actually want to support in this fdtable.
	 * Allocation steps are keyed to the size of the fdarray, since it
	 * grows far faster than any of the other dynamic data. We try to fit
	 * the fdarray into comfortable page-tuned chunks: starting at 1024B
	 * and growing in powers of two from there on.
	 */
	nr /= (1024 / sizeof(struct file *));
	nr = roundup_pow_of_two(nr + 1);
	nr *= (1024 / sizeof(struct file *));
	nr = ALIGN(nr, BITS_PER_LONG);
	/*
	 * Note that this can drive nr *below* what we had passed if sysctl_nr_open
	 * had been set lower between the check in expand_files() and here.  Deal
	 * with that in caller, it's cheaper that way.
	 *
	 * We make sure that nr remains a multiple of BITS_PER_LONG - otherwise
	 * bitmaps handling below becomes unpleasant, to put it mildly...
	 */
	if (unlikely(nr > sysctl_nr_open))
		nr = ((sysctl_nr_open - 1) | (BITS_PER_LONG - 1)) + 1;

	fdt = kmalloc(sizeof(struct fdtable), GFP_KERNEL_ACCOUNT);
	if (!fdt)
		goto out;
	fdt->max_fds = nr;
	data = kvmalloc_array(nr, sizeof(struct file *), GFP_KERNEL_ACCOUNT);
	if (!data)
		goto out_fdt;
	fdt->fd = data;

	data = kvmalloc(max_t(size_t,
				 2 * nr / BITS_PER_BYTE + BITBIT_SIZE(nr), L1_CACHE_BYTES),
				 GFP_KERNEL_ACCOUNT);
	if (!data)
		goto out_arr;
	fdt->open_fds = data;
	data += nr / BITS_PER_BYTE;
	fdt->close_on_exec = data;
	data += nr / BITS_PER_BYTE;
	fdt->full_fds_bits = data;

	return fdt;

out_arr:
	kvfree(fdt->fd);
out_fdt:
	kfree(fdt);
out:
	return NULL;
}
```


#### 修复函数（修复后）

```c
static struct fdtable * alloc_fdtable(unsigned int nr)
{
	struct fdtable *fdt;
	void *data;

	/*
	 * Figure out how many fds we actually want to support in this fdtable.
	 * Allocation steps are keyed to the size of the fdarray, since it
	 * grows far faster than any of the other dynamic data. We try to fit
	 * the fdarray into comfortable page-tuned chunks: starting at 1024B
	 * and growing in powers of two from there on.
	 */
	nr /= (1024 / sizeof(struct file *));
	nr = roundup_pow_of_two(nr + 1);
	nr *= (1024 / sizeof(struct file *));
	nr = ALIGN(nr, BITS_PER_LONG);
	/*
	 * Note that this can drive nr *below* what we had passed if sysctl_nr_open
	 * had been set lower between the check in expand_files() and here.  Deal
	 * with that in caller, it's cheaper that way.
	 *
	 * We make sure that nr remains a multiple of BITS_PER_LONG - otherwise
	 * bitmaps handling below becomes unpleasant, to put it mildly...
	 */
	if (unlikely(nr > sysctl_nr_open))
		nr = ((sysctl_nr_open - 1) | (BITS_PER_LONG - 1)) + 1;

	/*
	 * Check if the allocation size would exceed INT_MAX. kvmalloc_array()
	 * and kvmalloc() will warn if the allocation size is greater than
	 * INT_MAX, as filp_cachep objects are not __GFP_NOWARN.
	 *
	 * This can happen when sysctl_nr_open is set to a very high value and
	 * a process tries to use a file descriptor near that limit. For example,
	 * if sysctl_nr_open is set to 1073741816 (0x3ffffff8) - which is what
	 * systemd typically sets it to - then trying to use a file descriptor
	 * close to that value will require allocating a file descriptor table
	 * that exceeds 8GB in size.
	 */
	if (unlikely(nr > INT_MAX / sizeof(struct file *)))
		return ERR_PTR(-EMFILE);

	fdt = kmalloc(sizeof(struct fdtable), GFP_KERNEL_ACCOUNT);
	if (!fdt)
		goto out;
	fdt->max_fds = nr;
	data = kvmalloc_array(nr, sizeof(struct file *), GFP_KERNEL_ACCOUNT);
	if (!data)
		goto out_fdt;
	fdt->fd = data;

	data = kvmalloc(max_t(size_t,
				 2 * nr / BITS_PER_BYTE + BITBIT_SIZE(nr), L1_CACHE_BYTES),
				 GFP_KERNEL_ACCOUNT);
	if (!data)
		goto out_arr;
	fdt->open_fds = data;
	data += nr / BITS_PER_BYTE;
	fdt->close_on_exec = data;
	data += nr / BITS_PER_BYTE;
	fdt->full_fds_bits = data;

	return fdt;

out_arr:
	kvfree(fdt->fd);
out_fdt:
	kfree(fdt);
out:
	return NULL;
}
```


#### 关键变更行

```diff
+ 	/*
+ 	 * Check if the allocation size would exceed INT_MAX. kvmalloc_array()
+ 	 * and kvmalloc() will warn if the allocation size is greater than
+ 	 * INT_MAX, as filp_cachep objects are not __GFP_NOWARN.
+ 	 *
+ 	 * This can happen when sysctl_nr_open is set to a very high value and
+ 	 * a process tries to use a file descriptor near that limit. For example,
+ 	 * if sysctl_nr_open is set to 1073741816 (0x3ffffff8) - which is what
+ 	 * systemd typically sets it to - then trying to use a file descriptor
+ 	 * close to that value will require allocating a file descriptor table
+ 	 * that exceeds 8GB in size.
+ 	 */
+ 	if (unlikely(nr > INT_MAX / sizeof(struct file *)))
+ 		return ERR_PTR(-EMFILE);
+ 
```


---

<a id="cve202512726"></a>

## CVE-2025-12726  ·  chromium_src  ·  中危

**参考链接**：<https://gitcode.com/openharmony-tpc/chromium_src/pull/6319>

**漏洞描述**：_（未获取到描述，可能需要 GITCODE_PRIVATE_TOKEN 或 GITHUB_TOKEN）_


共涉及 **7** 个函数／代码区域：

### 1. `void WebContentsViewAura::StartDragging(`

**文件**：`content/browser/web_contents/web_contents_view_aura.cc`  |  **变更**：+14 / -0 行  |  ✅ 完整函数体（源文件已获取）

**Hunk 位置**：`@@ -1163,6 +1163,20 @@ void WebContentsViewAura::StartDragging(`


#### 漏洞函数（修复前）

```cpp
void WebContentsViewAura::StartDragging(
    const DropData& drop_data,
    const url::Origin& source_origin,
    blink::DragOperationsMask operations,
    const gfx::ImageSkia& image,
    const gfx::Vector2d& cursor_offset,
    const gfx::Rect& drag_obj_rect,
    const blink::mojom::DragEventSourceInfo& event_info,
    RenderWidgetHostImpl* source_rwh) {
  aura::Window* root_window = GetNativeView()->GetRootWindow();
  if (!aura::client::GetDragDropClient(root_window)) {
    web_contents_->SystemDragEnded(source_rwh);
    return;
  }

  // Grab a weak pointer to the RenderWidgetHost, since it can be destroyed
  // during the drag and drop nested run loop in StartDragAndDrop.
  // For example, the RenderWidgetHost can be deleted if a cross-process
  // transfer happens while dragging, since the RenderWidgetHost is deleted in
  // that case.
  base::WeakPtr<RenderWidgetHostImpl> source_rwh_weak_ptr =
      source_rwh->GetWeakPtr();
  base::WeakPtr<WebContentsViewAura> weak_this = weak_ptr_factory_.GetWeakPtr();

  drag_security_info_.OnDragInitiated(source_rwh, drop_data);

  ui::TouchSelectionController* selection_controller = GetSelectionController();
  if (selection_controller)
    selection_controller->HideAndDisallowShowingAutomatically();
  std::unique_ptr<ui::OSExchangeDataProvider> provider =
      ui::OSExchangeDataProviderFactory::CreateProvider();
  PrepareDragData(drop_data, source_origin, provider.get(), web_contents_);

  auto data = std::make_unique<ui::OSExchangeData>(std::move(provider));
  data->SetSource(std::make_unique<ui::DataTransferEndpoint>(
      web_contents_->GetPrimaryMainFrame()->GetLastCommittedURL(),
      ui::DataTransferEndpointOptions{
          .off_the_record =
              web_contents_->GetBrowserContext()->IsOffTheRecord()}));
  WebContentsDelegate* delegate = web_contents_->GetDelegate();
  if (delegate && delegate->IsPrivileged())
    data->MarkAsFromPrivileged();

  if (!image.isNull())
    data->provider().SetDragImage(image, cursor_offset);

  // TODO(crbug.com/40825138): The param `drag_obj_rect` is unused.

  std::unique_ptr<WebDragSourceAura> drag_source(
      new WebDragSourceAura(GetNativeView(), web_contents_));

  // We need to enable recursive tasks on the message loop so we can get
  // updates while in the system DoDragDrop loop.
  DragOperation result_op;
  {
    gfx::NativeView content_native_view = GetContentNativeView();
    base::CurrentThread::ScopedAllowApplicationTasksInNativeNestedLoop allow;
    result_op =
        aura::client::GetDragDropClient(root_window)
            ->StartDragAndDrop(std::move(data), root_window,
                               content_native_view, event_info.location,
                               ConvertFromDragOperationsMask(operations),
                               event_info.source);
  }

  // Bail out immediately if the contents view window is gone. Note that it is
  // not safe to access any class members in this case since |this| may already
  // be destroyed. The local variable |drag_source| will still be valid though,
  // so we can use it to determine if the window is gone.
  if (!drag_source->window()) {
    // Note that in this case, we don't need to call SystemDragEnded() since the
    // renderer is going away.
    return;
  }

  // |this| should still be alive at this point.
  CHECK(weak_this, base::NotFatalUntil::M130);

  // If drag is still in progress that means we haven't received drop targeting
  // callback yet. So we have to make sure to delay calling EndDrag until drop
  // is done.
  if (!drag_in_progress_) {
    EndDrag(std::move(source_rwh_weak_ptr), result_op);
  } else {
    end_drag_runner_.ReplaceClosure(
        base::BindOnce(&WebContentsViewAura::EndDrag, std::move(weak_this),
                       std::move(source_rwh_weak_ptr), result_op));
  }
}
```


#### 修复函数（修复后）

```cpp
void WebContentsViewAura::StartDragging(
    const DropData& drop_data,
    const url::Origin& source_origin,
    blink::DragOperationsMask operations,
    const gfx::ImageSkia& image,
    const gfx::Vector2d& cursor_offset,
    const gfx::Rect& drag_obj_rect,
    const blink::mojom::DragEventSourceInfo& event_info,
    RenderWidgetHostImpl* source_rwh) {
  aura::Window* root_window = GetNativeView()->GetRootWindow();
  if (!aura::client::GetDragDropClient(root_window)) {
    web_contents_->SystemDragEnded(source_rwh);
    return;
  }

  // Grab a weak pointer to the RenderWidgetHost, since it can be destroyed
  // during the drag and drop nested run loop in StartDragAndDrop.
  // For example, the RenderWidgetHost can be deleted if a cross-process
  // transfer happens while dragging, since the RenderWidgetHost is deleted in
  // that case.
  base::WeakPtr<RenderWidgetHostImpl> source_rwh_weak_ptr =
      source_rwh->GetWeakPtr();
  base::WeakPtr<WebContentsViewAura> weak_this = weak_ptr_factory_.GetWeakPtr();

  drag_security_info_.OnDragInitiated(source_rwh, drop_data);

  ui::TouchSelectionController* selection_controller = GetSelectionController();
  if (selection_controller)
    selection_controller->HideAndDisallowShowingAutomatically();
  std::unique_ptr<ui::OSExchangeDataProvider> provider =
      ui::OSExchangeDataProviderFactory::CreateProvider();
  PrepareDragData(drop_data, source_origin, provider.get(), web_contents_);

  auto data = std::make_unique<ui::OSExchangeData>(std::move(provider));
  data->SetSource(std::make_unique<ui::DataTransferEndpoint>(
      web_contents_->GetPrimaryMainFrame()->GetLastCommittedURL(),
      ui::DataTransferEndpointOptions{
          .off_the_record =
              web_contents_->GetBrowserContext()->IsOffTheRecord()}));
  WebContentsDelegate* delegate = web_contents_->GetDelegate();
  if (delegate && delegate->IsPrivileged())
    data->MarkAsFromPrivileged();

  if (!image.isNull())
    data->provider().SetDragImage(image, cursor_offset);

  // TODO(crbug.com/40825138): The param `drag_obj_rect` is unused.

  std::unique_ptr<WebDragSourceAura> drag_source(
      new WebDragSourceAura(GetNativeView(), web_contents_));

  // We need to enable recursive tasks on the message loop so we can get
  // updates while in the system DoDragDrop loop.
  DragOperation result_op;
  {
    gfx::NativeView content_native_view = GetContentNativeView();
    // Make sure event is within the web contents, and the web contents are
    // visible.
    if (
#if !BUILDFLAG(IS_CHROMEOS)
        // TODO(https://crbug.com/454552204): Remove #if when either ChromeOS
        // fixes split screen mode web ui tab strip drag, or web ui tab strip is
        // fully deprecated.
        !content_native_view->GetBoundsInScreen().Contains(
            event_info.location) ||
#endif  // !BUILDFLAG(IS_CHROMEOS)
        !content_native_view->IsVisible()) {
      web_contents_->SystemDragEnded(source_rwh);
      return;
    }    
    base::CurrentThread::ScopedAllowApplicationTasksInNativeNestedLoop allow;
    result_op =
        aura::client::GetDragDropClient(root_window)
            ->StartDragAndDrop(std::move(data), root_window,
                               content_native_view, event_info.location,
                               ConvertFromDragOperationsMask(operations),
                               event_info.source);
  }

  // Bail out immediately if the contents view window is gone. Note that it is
  // not safe to access any class members in this case since |this| may already
  // be destroyed. The local variable |drag_source| will still be valid though,
  // so we can use it to determine if the window is gone.
  if (!drag_source->window()) {
    // Note that in this case, we don't need to call SystemDragEnded() since the
    // renderer is going away.
    return;
  }

  // |this| should still be alive at this point.
  CHECK(weak_this, base::NotFatalUntil::M130);

  // If drag is still in progress that means we haven't received drop targeting
  // callback yet. So we have to make sure to delay calling EndDrag until drop
  // is done.
  if (!drag_in_progress_) {
    EndDrag(std::move(source_rwh_weak_ptr), result_op);
  } else {
    end_drag_runner_.ReplaceClosure(
        base::BindOnce(&WebContentsViewAura::EndDrag, std::move(weak_this),
                       std::move(source_rwh_weak_ptr), result_op));
  }
}
```


#### 关键变更行

```diff
+     // Make sure event is within the web contents, and the web contents are
+     // visible.
+     if (
+ #if !BUILDFLAG(IS_CHROMEOS)
+         // TODO(https://crbug.com/454552204): Remove #if when either ChromeOS
+         // fixes split screen mode web ui tab strip drag, or web ui tab strip is
+         // fully deprecated.
+         !content_native_view->GetBoundsInScreen().Contains(
+             event_info.location) ||
+ #endif  // !BUILDFLAG(IS_CHROMEOS)
+         !content_native_view->IsVisible()) {
+       web_contents_->SystemDragEnded(source_rwh);
+       return;
+     }    
```


---

### 2. `class CONTENT_EXPORT WebContentsViewAura`

**文件**：`content/browser/web_contents/web_contents_view_aura.h`  |  **变更**：+3 / -0 行  |  ✅ 完整函数体（源文件已获取）

**Hunk 位置**：`@@ -164,6 +164,9 @@ class CONTENT_EXPORT WebContentsViewAura`


#### 漏洞函数（修复前）

```c
class CONTENT_EXPORT WebContentsViewAura
    : public WebContentsView,
      public RenderViewHostDelegateView,
      public aura::WindowDelegate,
      public aura::client::DragDropDelegate {
 public:
  WebContentsViewAura(WebContentsImpl* web_contents,
                      std::unique_ptr<WebContentsViewDelegate> delegate);
  ~WebContentsViewAura() override;

  WebContentsViewAura(const WebContentsViewAura&) = delete;
  WebContentsViewAura& operator=(const WebContentsViewAura&) = delete;

  // Allow the WebContentsViewDelegate to be set explicitly.
  void SetDelegateForTesting(std::unique_ptr<WebContentsViewDelegate> delegate);

  // Set a flag to pass nullptr as the parent_view argument to
  // RenderWidgetHostViewAura::InitAsChild().
  void set_init_rwhv_with_null_parent_for_testing(bool set) {
    init_rwhv_with_null_parent_for_testing_ = set;
  }

  using RenderWidgetHostViewCreateFunction =
      RenderWidgetHostViewAura* (*)(RenderWidgetHost*);

  // Used to override the creation of RenderWidgetHostViews in tests.
  static void InstallCreateHookForTests(
      RenderWidgetHostViewCreateFunction create_render_widget_host_view);

 private:
  // Just the metadata from DropTargetEvent that's safe and cheap to copy to
  // help locate drop events in the callback.
  struct DropMetadata {
    explicit DropMetadata(const ui::DropTargetEvent& event);

    // Location local to WebContentsViewAura.
    gfx::PointF localized_location;

    // Root location of the drop target event.
    gfx::PointF root_location;

    // The supported DnD operation of the source. A bitmask of
    // ui::mojom::DragOperations.
    int source_operations;
    // Flags from ui::Event. Usually represents modifier keys used at drop time.
    int flags;
  };

  // A structure used to keep drop context for asynchronously finishing a
  // drop operation.  This is required because some drop event data gets
  // cleared out once PerformDropCallback() returns.
  struct CONTENT_EXPORT OnPerformingDropContext {
    OnPerformingDropContext(RenderWidgetHostImpl* target_rwh,
                            std::unique_ptr<DropData> drop_data,
                            DropMetadata drop_metadata,
                            std::unique_ptr<ui::OSExchangeData> data,
                            base::ScopedClosureRunner end_drag_runner,
                            std::optional<gfx::PointF> transformed_pt,
                            gfx::PointF screen_pt);
    OnPerformingDropContext(const OnPerformingDropContext& other) = delete;
    OnPerformingDropContext(OnPerformingDropContext&& other);
    OnPerformingDropContext& operator=(const OnPerformingDropContext& other) =
        delete;
    ~OnPerformingDropContext();

    base::WeakPtr<RenderWidgetHostImpl> target_rwh;
    std::unique_ptr<DropData> drop_data;
    DropMetadata drop_metadata;
    std::unique_ptr<ui::OSExchangeData> data;
    base::ScopedClosureRunner end_drag_runner;
    std::optional<gfx::PointF> transformed_pt;
    gfx::PointF screen_pt;
  };

  friend class WebContentsViewAuraTest;
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest, EnableDisableOverscroll);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest, RenderViewHostChanged);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest, DragDropFiles);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest,
                           DragDropFilesOriginateFromRenderer);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest, DragDropImageFromRenderer);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest, DragDropVirtualFiles);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest,
                           DragDropVirtualFilesOriginateFromRenderer);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest, DragDropUrlData);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest, DragDropOnOopif);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest,
                           Drop_NoDropZone_DelegateAllows);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest,
                           Drop_NoDropZone_DelegateBlocks);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest,
                           Drop_DropZone_DelegateAllow);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest,
                           Drop_DropZone_DelegateBlocks);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest, StartDragging);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest, GetDropCallback_Run);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest, GetDropCallback_Cancelled);
  FRIEND_TEST_ALL_PREFIXES(
      WebContentsViewAuraTest,
      RejectDragFromPrivilegedWebContentsToNonPrivilegedWebContents);
  FRIEND_TEST_ALL_PREFIXES(
      WebContentsViewAuraTest,
      AcceptDragFromPrivilegedWebContentsToPrivilegedWebContents);
  FRIEND_TEST_ALL_PREFIXES(
      WebContentsViewAuraTest,
      RejectDragFromNonPrivilegedWebContentsToPrivilegedWebContents);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest,
                           StartDragFromPrivilegedWebContents);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest,
                           EmptyTextInDropDataIsNonNullInOSExchangeData);
  FRIEND_TEST_ALL_PREFIXES(
      WebContentsViewAuraTest,
      EmptyTextWithUrlInDropDataIsEmptyInOSExchangeDataGetString);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest,
                           UrlInDropDataReturnsUrlInOSExchangeDataGetString);

  class WindowObserver;

  // Utility to fill a DropData object from ui::OSExchangeData.
  void PrepareDropData(DropData* drop_data,
                       const ui::OSExchangeData& data) const;

  void EndDrag(base::WeakPtr<RenderWidgetHostImpl> source_rwh_weak_ptr,
               ui::mojom::DragOperation op);

  void InstallOverscrollControllerDelegate(RenderWidgetHostViewAura* view);

  ui::TouchSelectionController* GetSelectionController() const;
  TouchSelectionControllerClientAura* GetSelectionControllerClient() const;

  // Returns GetNativeView unless overridden for testing.
  gfx::NativeView GetRenderWidgetHostViewParent() const;

  // Called from CreateView() to create |window_|.
  void CreateAuraWindow(aura::Window* context);

  // Computes the view's visibility updates the WebContents accordingly.
  void UpdateWebContentsVisibility();

  // Computes the view's visibility.
  Visibility GetVisibility() const;

  // Overridden from WebContentsView:
  gfx::NativeView GetNativeView() const override;
  gfx::NativeView GetContentNativeView() const override;
  gfx::NativeWindow GetTopLevelNativeWindow() const override;
  gfx::Rect GetContainerBounds() const override;
  void Focus() override;
  void SetInitialFocus() override;
  void StoreFocus() override;
  void RestoreFocus() override;
  void FocusThroughTabTraversal(bool reverse) override;
  DropData* GetDropData() const override;
  gfx::Rect GetViewBounds() const override;
  void CreateView(gfx::NativeView context) override;
  RenderWidgetHostViewBase* CreateViewForWidget(
      RenderWidgetHost* render_widget_host) override;
  RenderWidgetHostViewBase* CreateViewForChildWidget(
      RenderWidgetHost* render_widget_host) override;
  void SetPageTitle(const std::u16string& title) override;
  void RenderViewReady() override;
  void RenderViewHostChanged(RenderViewHost* old_host,
                             RenderViewHost* new_host) override;
  void SetOverscrollControllerEnabled(bool enabled) override;
  void OnCapturerCountChanged() override;
  void FullscreenStateChanged(bool is_fullscreen) override;
  void UpdateWindowControlsOverlay(const gfx::Rect& bounding_rect) override;
  BackForwardTransitionAnimationManager*
  GetBackForwardTransitionAnimationManager() override;
  void DestroyBackForwardTransitionAnimationManager() override;

  // Overridden from RenderViewHostDelegateView:
  void ShowContextMenu(RenderFrameHost& render_frame_host,
                       const ContextMenuParams& params) override;
  void StartDragging(const DropData& drop_data,
                     const url::Origin& source_origin,
                     blink::DragOperationsMask operations,
                     const gfx::ImageSkia& image,
                     const gfx::Vector2d& cursor_offset,
                     const gfx::Rect& drag_obj_rect,
                     const blink::mojom::DragEventSourceInfo& event_info,
                     RenderWidgetHostImpl* source_rwh) override;
  void UpdateDragOperation(ui::mojom::DragOperation operation,
                           bool document_is_handling_drag) override;
  void GotFocus(RenderWidgetHostImpl* render_widget_host) override;
  void LostFocus(RenderWidgetHostImpl* render_widget_host) override;
  void TakeFocus(bool reverse) override;
#if BUILDFLAG(ARKWEB_EXT_TOPCONTROLS)
  int GetTopControlsHeight() override;
#else
  int GetTopControlsHeight() const override;
#endif
  int GetBottomControlsHeight() const override;
  bool DoBrowserControlsShrinkRendererSize() const override;
#if BUILDFLAG(USE_EXTERNAL_POPUP_MENU)
  void ShowPopupMenu(
      RenderFrameHost* render_frame_host,
      mojo::PendingRemote<blink::mojom::PopupMenuClient> popup_client,
      const gfx::Rect& bounds,
      int item_height,
      double item_font_size,
      int selected_item,
      std::vector<blink::mojom::MenuItemPtr> menu_items,
      bool right_aligned,
      bool allow_multiple_selection) override;
#endif

  // Overridden from aura::WindowDelegate:
  gfx::Size GetMinimumSize() const override;
  gfx::Size GetMaximumSize() const override;
  void OnBoundsChanged(const gfx::Rect& old_bounds,
                       const gfx::Rect& new_bounds) override;
  gfx::NativeCursor GetCursor(const gfx::Point& point) override;
  int GetNonClientComponent(const gfx::Point& point) const override;
  bool ShouldDescendIntoChildForEventHandling(
      aura::Window* child,
      const gfx::Point& location) override;
  bool CanFocus() override;
  void OnCaptureLost() override;
  void OnPaint(const ui::PaintContext& context) override;
  void OnDeviceScaleFactorChanged(float old_device_scale_factor,
                                  float new_device_scale_factor) override;
  void OnWindowDestroying(aura::Window* window) override;
  void OnWindowDestroyed(aura::Window* window) override;
  void OnWindowTargetVisibilityChanged(bool visible) override;
  void OnWindowOcclusionChanged(
      aura::Window::OcclusionState old_occlusion_state,
      aura::Window::OcclusionState new_occlusion_state) override;
  bool HasHitTestMask() const override;
  void GetHitTestMask(SkPath* mask) const override;

  // Overridden from ui::EventHandler:
  void OnKeyEvent(ui::KeyEvent* event) override;
  void OnMouseEvent(ui::MouseEvent* event) override;

  // Overridden from aura::client::DragDropDelegate:
  void OnDragEntered(const ui::DropTargetEvent& event) override;
  aura::client::DragUpdateInfo OnDragUpdated(
      const ui::DropTargetEvent& event) override;
  void OnDragExited() override;
  aura::client::DragDropDelegate::DropCallback GetDropCallback(
      const ui::DropTargetEvent& event) override;

  void DragEnteredCallback(DropMetadata flags,
                           std::unique_ptr<DropData> drop_data,
                           base::WeakPtr<RenderWidgetHostViewBase> target,
                           std::optional<gfx::PointF> transformed_pt);
  void DragUpdatedCallback(DropMetadata drop_metadata,
                           std::unique_ptr<DropData> drop_data,
                           base::WeakPtr<RenderWidgetHostViewBase> target,
                           std::optional<gfx::PointF> transformed_pt);
  void PerformDropCallback(DropMetadata drop_metadata,
                           std::unique_ptr<ui::OSExchangeData> data,
                           base::WeakPtr<RenderWidgetHostViewBase> target,
                           std::optional<gfx::PointF> transformed_pt);

  // Completes a drag exit operation by communicating with the renderer process.
  void CompleteDragExit();

  // Called from MaybeLetDelegateProcessDrop() to finish processing the drop.
  // The override with `drop_data` updates `current_drag_data_` before
  // completing the drop.
  void GotModifiedDropDataFromDelegate(OnPerformingDropContext drop_context,
                                       std::optional<DropData> drop_data);

  // Completes a drop operation by communicating the drop data to the renderer
  // process.
  void CompleteDrop(OnPerformingDropContext drop_context);

  // Performs drop if it's run. Otherwise, it exits the drag. Returned by
  // GetDropCallback.
  void PerformDropOrExitDrag(
      base::ScopedClosureRunner exit_drag,
      DropMetadata drop_metadata,
      std::unique_ptr<ui::OSExchangeData> data,
      ui::mojom::DragOperation& output_drag_op,
      std::unique_ptr<ui::LayerTreeOwner> drag_image_layer_owner);

  // For unit testing, registers a callback for when a drop operation
  // completes.
  using DropCallbackForTesting =
      base::OnceCallback<void(RenderWidgetHostImpl* target_rwh,
                              const DropData& drop_data,
                              const gfx::PointF& client_pt,
                              const gfx::PointF& screen_pt,
                              int key_modifiers,
                              bool drop_allowed)>;
  void RegisterDropCallbackForTesting(DropCallbackForTesting callback);

  void SetDragDestDelegateForTesting(WebDragDestDelegate* delegate) {
    drag_dest_delegate_ = delegate;
  }

#if BUILDFLAG(IS_WIN)
  // Callback for asynchronous retrieval of virtual files.
  void OnGotVirtualFilesAsTempFiles(
      OnPerformingDropContext drop_context,
      const std::vector<std::pair</*temp path*/ base::FilePath,
                                  /*display name*/ base::FilePath>>&
          filepaths_and_names);

  class AsyncDropNavigationObserver;
  std::unique_ptr<AsyncDropNavigationObserver> async_drop_navigation_observer_;

  class AsyncDropTempFileDeleter;
  std::unique_ptr<AsyncDropTempFileDeleter> async_drop_temp_file_deleter_;
#endif
  DropCallbackForTesting drop_callback_for_testing_;

  // Calls the delegate's OnPerformingDrop() if a delegate is present, otherwise
  // finishes performing the drop by calling FinishOnPerformingDrop().
  void MaybeLetDelegateProcessDrop(OnPerformingDropContext drop_context);

  // If this callback is initialized it must be run after the drop operation is
  // done to send dragend event in EndDrag function.
  base::ScopedClosureRunner end_drag_runner_;

  std::unique_ptr<aura::Window> window_;

  std::unique_ptr<WindowObserver> window_observer_;

  // The WebContentsImpl whose contents we display.
  const raw_ptr<WebContentsImpl> web_contents_;

  std::unique_ptr<WebContentsViewDelegate> delegate_;

  // This member holds the dropped data from the drag enter phase to the end
  // of the drop.  A drop may end if the user releases the mouse button over
  // the view, if the cursor moves off the view, or some other events occurs
  // like a change in the RWH.  This member is null when no drop is happening.
  std::unique_ptr<DropData> current_drag_data_;

  raw_ptr<WebDragDestDelegate> drag_dest_delegate_;

  // We keep track of the RenderWidgetHost we're dragging over. If it changes
  // during a drag, we need to re-send the DragEnter message.
  base::WeakPtr<RenderWidgetHostImpl> current_rwh_for_drag_;

  // We also keep track of the ID of the RenderViewHost we're dragging over to
  // avoid sending the drag exited message after leaving the current view.
  GlobalRoutingID current_rvh_for_drag_;

  // Holds the security info for the current drag.
  WebContentsViewDragSecurityInfo drag_security_info_;

  // Responsible for handling gesture-nav and pull-to-refresh UI.
  std::unique_ptr<GestureNavSimple> gesture_nav_simple_;

  // This is true when the drag is in process from the perspective of this
  // class. It means it gets true when drag enters and gets reset when either
  // drop happens or drag exits.
  bool drag_in_progress_;

  bool init_rwhv_with_null_parent_for_testing_;

  // Non-null when the WebContents is being captured for video.
  std::unique_ptr<aura::WindowTreeHost::VideoCaptureLock> video_capture_lock_;

  base::WeakPtrFactory<WebContentsViewAura> weak_ptr_factory_{this};
};
```


#### 修复函数（修复后）

```c
class CONTENT_EXPORT WebContentsViewAura
    : public WebContentsView,
      public RenderViewHostDelegateView,
      public aura::WindowDelegate,
      public aura::client::DragDropDelegate {
 public:
  WebContentsViewAura(WebContentsImpl* web_contents,
                      std::unique_ptr<WebContentsViewDelegate> delegate);
  ~WebContentsViewAura() override;

  WebContentsViewAura(const WebContentsViewAura&) = delete;
  WebContentsViewAura& operator=(const WebContentsViewAura&) = delete;

  // Allow the WebContentsViewDelegate to be set explicitly.
  void SetDelegateForTesting(std::unique_ptr<WebContentsViewDelegate> delegate);

  // Set a flag to pass nullptr as the parent_view argument to
  // RenderWidgetHostViewAura::InitAsChild().
  void set_init_rwhv_with_null_parent_for_testing(bool set) {
    init_rwhv_with_null_parent_for_testing_ = set;
  }

  using RenderWidgetHostViewCreateFunction =
      RenderWidgetHostViewAura* (*)(RenderWidgetHost*);

  // Used to override the creation of RenderWidgetHostViews in tests.
  static void InstallCreateHookForTests(
      RenderWidgetHostViewCreateFunction create_render_widget_host_view);

 private:
  // Just the metadata from DropTargetEvent that's safe and cheap to copy to
  // help locate drop events in the callback.
  struct DropMetadata {
    explicit DropMetadata(const ui::DropTargetEvent& event);

    // Location local to WebContentsViewAura.
    gfx::PointF localized_location;

    // Root location of the drop target event.
    gfx::PointF root_location;

    // The supported DnD operation of the source. A bitmask of
    // ui::mojom::DragOperations.
    int source_operations;
    // Flags from ui::Event. Usually represents modifier keys used at drop time.
    int flags;
  };

  // A structure used to keep drop context for asynchronously finishing a
  // drop operation.  This is required because some drop event data gets
  // cleared out once PerformDropCallback() returns.
  struct CONTENT_EXPORT OnPerformingDropContext {
    OnPerformingDropContext(RenderWidgetHostImpl* target_rwh,
                            std::unique_ptr<DropData> drop_data,
                            DropMetadata drop_metadata,
                            std::unique_ptr<ui::OSExchangeData> data,
                            base::ScopedClosureRunner end_drag_runner,
                            std::optional<gfx::PointF> transformed_pt,
                            gfx::PointF screen_pt);
    OnPerformingDropContext(const OnPerformingDropContext& other) = delete;
    OnPerformingDropContext(OnPerformingDropContext&& other);
    OnPerformingDropContext& operator=(const OnPerformingDropContext& other) =
        delete;
    ~OnPerformingDropContext();

    base::WeakPtr<RenderWidgetHostImpl> target_rwh;
    std::unique_ptr<DropData> drop_data;
    DropMetadata drop_metadata;
    std::unique_ptr<ui::OSExchangeData> data;
    base::ScopedClosureRunner end_drag_runner;
    std::optional<gfx::PointF> transformed_pt;
    gfx::PointF screen_pt;
  };

  friend class WebContentsViewAuraTest;
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest, EnableDisableOverscroll);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest, RenderViewHostChanged);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest, DragDropFiles);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest,
                           DragDropFilesOriginateFromRenderer);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest, DragDropImageFromRenderer);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest, DragDropVirtualFiles);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest,
                           DragDropVirtualFilesOriginateFromRenderer);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest, DragDropUrlData);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest, DragDropOnOopif);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest,
                           Drop_NoDropZone_DelegateAllows);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest,
                           Drop_NoDropZone_DelegateBlocks);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest,
                           Drop_DropZone_DelegateAllow);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest,
                           Drop_DropZone_DelegateBlocks);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest, StartDragging);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest, GetDropCallback_Run);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest, GetDropCallback_Cancelled);
  FRIEND_TEST_ALL_PREFIXES(
      WebContentsViewAuraTest,
      RejectDragFromPrivilegedWebContentsToNonPrivilegedWebContents);
  FRIEND_TEST_ALL_PREFIXES(
      WebContentsViewAuraTest,
      AcceptDragFromPrivilegedWebContentsToPrivilegedWebContents);
  FRIEND_TEST_ALL_PREFIXES(
      WebContentsViewAuraTest,
      RejectDragFromNonPrivilegedWebContentsToPrivilegedWebContents);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest,
                           StartDragFromPrivilegedWebContents);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest,
                           EmptyTextInDropDataIsNonNullInOSExchangeData);
  FRIEND_TEST_ALL_PREFIXES(
      WebContentsViewAuraTest,
      EmptyTextWithUrlInDropDataIsEmptyInOSExchangeDataGetString);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest,
                           RejectDragFromHiddenWebContents);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest, RejectDragFromOutsideView);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest,
                           UrlInDropDataReturnsUrlInOSExchangeDataGetString);

  class WindowObserver;

  // Utility to fill a DropData object from ui::OSExchangeData.
  void PrepareDropData(DropData* drop_data,
                       const ui::OSExchangeData& data) const;

  void EndDrag(base::WeakPtr<RenderWidgetHostImpl> source_rwh_weak_ptr,
               ui::mojom::DragOperation op);

  void InstallOverscrollControllerDelegate(RenderWidgetHostViewAura* view);

  ui::TouchSelectionController* GetSelectionController() const;
  TouchSelectionControllerClientAura* GetSelectionControllerClient() const;

  // Returns GetNativeView unless overridden for testing.
  gfx::NativeView GetRenderWidgetHostViewParent() const;

  // Called from CreateView() to create |window_|.
  void CreateAuraWindow(aura::Window* context);

  // Computes the view's visibility updates the WebContents accordingly.
  void UpdateWebContentsVisibility();

  // Computes the view's visibility.
  Visibility GetVisibility() const;

  // Overridden from WebContentsView:
  gfx::NativeView GetNativeView() const override;
  gfx::NativeView GetContentNativeView() const override;
  gfx::NativeWindow GetTopLevelNativeWindow() const override;
  gfx::Rect GetContainerBounds() const override;
  void Focus() override;
  void SetInitialFocus() override;
  void StoreFocus() override;
  void RestoreFocus() override;
  void FocusThroughTabTraversal(bool reverse) override;
  DropData* GetDropData() const override;
  gfx::Rect GetViewBounds() const override;
  void CreateView(gfx::NativeView context) override;
  RenderWidgetHostViewBase* CreateViewForWidget(
      RenderWidgetHost* render_widget_host) override;
  RenderWidgetHostViewBase* CreateViewForChildWidget(
      RenderWidgetHost* render_widget_host) override;
  void SetPageTitle(const std::u16string& title) override;
  void RenderViewReady() override;
  void RenderViewHostChanged(RenderViewHost* old_host,
                             RenderViewHost* new_host) override;
  void SetOverscrollControllerEnabled(bool enabled) override;
  void OnCapturerCountChanged() override;
  void FullscreenStateChanged(bool is_fullscreen) override;
  void UpdateWindowControlsOverlay(const gfx::Rect& bounding_rect) override;
  BackForwardTransitionAnimationManager*
  GetBackForwardTransitionAnimationManager() override;
  void DestroyBackForwardTransitionAnimationManager() override;

  // Overridden from RenderViewHostDelegateView:
  void ShowContextMenu(RenderFrameHost& render_frame_host,
                       const ContextMenuParams& params) override;
  void StartDragging(const DropData& drop_data,
                     const url::Origin& source_origin,
                     blink::DragOperationsMask operations,
                     const gfx::ImageSkia& image,
                     const gfx::Vector2d& cursor_offset,
                     const gfx::Rect& drag_obj_rect,
                     const blink::mojom::DragEventSourceInfo& event_info,
                     RenderWidgetHostImpl* source_rwh) override;
  void UpdateDragOperation(ui::mojom::DragOperation operation,
                           bool document_is_handling_drag) override;
  void GotFocus(RenderWidgetHostImpl* render_widget_host) override;
  void LostFocus(RenderWidgetHostImpl* render_widget_host) override;
  void TakeFocus(bool reverse) override;
#if BUILDFLAG(ARKWEB_EXT_TOPCONTROLS)
  int GetTopControlsHeight() override;
#else
  int GetTopControlsHeight() const override;
#endif
  int GetBottomControlsHeight() const override;
  bool DoBrowserControlsShrinkRendererSize() const override;
#if BUILDFLAG(USE_EXTERNAL_POPUP_MENU)
  void ShowPopupMenu(
      RenderFrameHost* render_frame_host,
      mojo::PendingRemote<blink::mojom::PopupMenuClient> popup_client,
      const gfx::Rect& bounds,
      int item_height,
      double item_font_size,
      int selected_item,
      std::vector<blink::mojom::MenuItemPtr> menu_items,
      bool right_aligned,
      bool allow_multiple_selection) override;
#endif

  // Overridden from aura::WindowDelegate:
  gfx::Size GetMinimumSize() const override;
  gfx::Size GetMaximumSize() const override;
  void OnBoundsChanged(const gfx::Rect& old_bounds,
                       const gfx::Rect& new_bounds) override;
  gfx::NativeCursor GetCursor(const gfx::Point& point) override;
  int GetNonClientComponent(const gfx::Point& point) const override;
  bool ShouldDescendIntoChildForEventHandling(
      aura::Window* child,
      const gfx::Point& location) override;
  bool CanFocus() override;
  void OnCaptureLost() override;
  void OnPaint(const ui::PaintContext& context) override;
  void OnDeviceScaleFactorChanged(float old_device_scale_factor,
                                  float new_device_scale_factor) override;
  void OnWindowDestroying(aura::Window* window) override;
  void OnWindowDestroyed(aura::Window* window) override;
  void OnWindowTargetVisibilityChanged(bool visible) override;
  void OnWindowOcclusionChanged(
      aura::Window::OcclusionState old_occlusion_state,
      aura::Window::OcclusionState new_occlusion_state) override;
  bool HasHitTestMask() const override;
  void GetHitTestMask(SkPath* mask) const override;

  // Overridden from ui::EventHandler:
  void OnKeyEvent(ui::KeyEvent* event) override;
  void OnMouseEvent(ui::MouseEvent* event) override;

  // Overridden from aura::client::DragDropDelegate:
  void OnDragEntered(const ui::DropTargetEvent& event) override;
  aura::client::DragUpdateInfo OnDragUpdated(
      const ui::DropTargetEvent& event) override;
  void OnDragExited() override;
  aura::client::DragDropDelegate::DropCallback GetDropCallback(
      const ui::DropTargetEvent& event) override;

  void DragEnteredCallback(DropMetadata flags,
                           std::unique_ptr<DropData> drop_data,
                           base::WeakPtr<RenderWidgetHostViewBase> target,
                           std::optional<gfx::PointF> transformed_pt);
  void DragUpdatedCallback(DropMetadata drop_metadata,
                           std::unique_ptr<DropData> drop_data,
                           base::WeakPtr<RenderWidgetHostViewBase> target,
                           std::optional<gfx::PointF> transformed_pt);
  void PerformDropCallback(DropMetadata drop_metadata,
                           std::unique_ptr<ui::OSExchangeData> data,
                           base::WeakPtr<RenderWidgetHostViewBase> target,
                           std::optional<gfx::PointF> transformed_pt);

  // Completes a drag exit operation by communicating with the renderer process.
  void CompleteDragExit();

  // Called from MaybeLetDelegateProcessDrop() to finish processing the drop.
  // The override with `drop_data` updates `current_drag_data_` before
  // completing the drop.
  void GotModifiedDropDataFromDelegate(OnPerformingDropContext drop_context,
                                       std::optional<DropData> drop_data);

  // Completes a drop operation by communicating the drop data to the renderer
  // process.
  void CompleteDrop(OnPerformingDropContext drop_context);

  // Performs drop if it's run. Otherwise, it exits the drag. Returned by
  // GetDropCallback.
  void PerformDropOrExitDrag(
      base::ScopedClosureRunner exit_drag,
      DropMetadata drop_metadata,
      std::unique_ptr<ui::OSExchangeData> data,
      ui::mojom::DragOperation& output_drag_op,
      std::unique_ptr<ui::LayerTreeOwner> drag_image_layer_owner);

  // For unit testing, registers a callback for when a drop operation
  // completes.
  using DropCallbackForTesting =
      base::OnceCallback<void(RenderWidgetHostImpl* target_rwh,
                              const DropData& drop_data,
                              const gfx::PointF& client_pt,
                              const gfx::PointF& screen_pt,
                              int key_modifiers,
                              bool drop_allowed)>;
  void RegisterDropCallbackForTesting(DropCallbackForTesting callback);

  void SetDragDestDelegateForTesting(WebDragDestDelegate* delegate) {
    drag_dest_delegate_ = delegate;
  }

#if BUILDFLAG(IS_WIN)
  // Callback for asynchronous retrieval of virtual files.
  void OnGotVirtualFilesAsTempFiles(
      OnPerformingDropContext drop_context,
      const std::vector<std::pair</*temp path*/ base::FilePath,
                                  /*display name*/ base::FilePath>>&
          filepaths_and_names);

  class AsyncDropNavigationObserver;
  std::unique_ptr<AsyncDropNavigationObserver> async_drop_navigation_observer_;

  class AsyncDropTempFileDeleter;
  std::unique_ptr<AsyncDropTempFileDeleter> async_drop_temp_file_deleter_;
#endif
  DropCallbackForTesting drop_callback_for_testing_;

  // Calls the delegate's OnPerformingDrop() if a delegate is present, otherwise
  // finishes performing the drop by calling FinishOnPerformingDrop().
  void MaybeLetDelegateProcessDrop(OnPerformingDropContext drop_context);

  // If this callback is initialized it must be run after the drop operation is
  // done to send dragend event in EndDrag function.
  base::ScopedClosureRunner end_drag_runner_;

  std::unique_ptr<aura::Window> window_;

  std::unique_ptr<WindowObserver> window_observer_;

  // The WebContentsImpl whose contents we display.
  const raw_ptr<WebContentsImpl> web_contents_;

  std::unique_ptr<WebContentsViewDelegate> delegate_;

  // This member holds the dropped data from the drag enter phase to the end
  // of the drop.  A drop may end if the user releases the mouse button over
  // the view, if the cursor moves off the view, or some other events occurs
  // like a change in the RWH.  This member is null when no drop is happening.
  std::unique_ptr<DropData> current_drag_data_;

  raw_ptr<WebDragDestDelegate> drag_dest_delegate_;

  // We keep track of the RenderWidgetHost we're dragging over. If it changes
  // during a drag, we need to re-send the DragEnter message.
  base::WeakPtr<RenderWidgetHostImpl> current_rwh_for_drag_;

  // We also keep track of the ID of the RenderViewHost we're dragging over to
  // avoid sending the drag exited message after leaving the current view.
  GlobalRoutingID current_rvh_for_drag_;

  // Holds the security info for the current drag.
  WebContentsViewDragSecurityInfo drag_security_info_;

  // Responsible for handling gesture-nav and pull-to-refresh UI.
  std::unique_ptr<GestureNavSimple> gesture_nav_simple_;

  // This is true when the drag is in process from the perspective of this
  // class. It means it gets true when drag enters and gets reset when either
  // drop happens or drag exits.
  bool drag_in_progress_;

  bool init_rwhv_with_null_parent_for_testing_;

  // Non-null when the WebContents is being captured for video.
  std::unique_ptr<aura::WindowTreeHost::VideoCaptureLock> video_capture_lock_;

  base::WeakPtrFactory<WebContentsViewAura> weak_ptr_factory_{this};
};
```


#### 关键变更行

```diff
+   FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest,
+                            RejectDragFromHiddenWebContents);
+   FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest, RejectDragFromOutsideView);
```


---

### 3. `class WebContentsViewAuraTest : public RenderViewHostTestHarness {`

**文件**：`content/browser/web_contents/web_contents_view_aura_unittest.cc`  |  **变更**：+1 / -0 行  |  ✅ 完整函数体（源文件已获取）

**Hunk 位置**：`@@ -144,6 +144,7 @@ class WebContentsViewAuraTest : public RenderViewHostTestHarness {`


#### 漏洞函数（修复前）

```cpp
/* patch context - source file unavailable */
/* ... line 144 ... */
  144      root_window()->SetBounds(kBounds);
  145      GetNativeView()->SetBounds(kBounds);
  146      GetNativeView()->Show();
  147      root_window()->AddChild(GetNativeView());
  148  
  149      occluding_window_.reset(aura::test::CreateTestWindowWithDelegateAndType(
```


#### 修复函数（修复后）

```cpp
/* patch context - source file unavailable */
/* ... line 144 ... */
  144      root_window()->SetBounds(kBounds);
  145      GetNativeView()->SetBounds(kBounds);
  146      GetNativeView()->Show();
  147      GetView()->GetContentNativeView()->Show();
  148      root_window()->AddChild(GetNativeView());
  149  
  150      occluding_window_.reset(aura::test::CreateTestWindowWithDelegateAndType(
```


#### 关键变更行

```diff
+     GetView()->GetContentNativeView()->Show();
```


---

### 4. `TEST_F(WebContentsViewAuraTest, StartDragFromPrivilegedWebContents) {`

**文件**：`content/browser/web_contents/web_contents_view_aura_unittest.cc`  |  **变更**：+77 / -0 行  |  ✅ 完整函数体（源文件已获取）

**Hunk 位置**：`@@ -846,6 +847,83 @@ TEST_F(WebContentsViewAuraTest, StartDragFromPrivilegedWebContents) {`


#### 漏洞函数（修复前）

```cpp
/* patch context - source file unavailable */
/* ... line 846 ... */
  846    EXPECT_TRUE(exchange_data->IsFromPrivileged());
  847  }
  848  
  849  TEST_F(WebContentsViewAuraTest, EmptyTextInDropDataIsNonNullInOSExchangeData) {
  850    const char kGoogleUrl[] = "https://google.com/";
  851
```


#### 修复函数（修复后）

```cpp
/* patch context - source file unavailable */
/* ... line 847 ... */
  847    EXPECT_TRUE(exchange_data->IsFromPrivileged());
  848  }
  849  
  850  TEST_F(WebContentsViewAuraTest, RejectDragFromHiddenWebContents) {
  851    const char kGoogleUrl[] = "https://google.com/";
  852  
  853    std::u16string url_string = u"https://google.com/";
  854  
  855    NavigateAndCommit(GURL(kGoogleUrl));
  856  
  857    TestDragDropClient drag_drop_client;
  858    aura::client::SetDragDropClient(root_window(), &drag_drop_client);
  859  
  860    // Mark the Web Contents as native UI.
  861    WebContentsViewAura* view = GetView();
  862  
  863    DropData drop_data;
  864    drop_data.url_infos = {ui::ClipboardUrlInfo{GURL(kGoogleUrl), u""}};
  865  
  866    view->GetContentNativeView()->Hide();
  867    view->StartDragging(drop_data, url::Origin::Create(GURL(kGoogleUrl)),
  868                        blink::DragOperationsMask::kDragOperationNone,
  869                        gfx::ImageSkia(), gfx::Vector2d(), gfx::Rect(),
  870                        blink::mojom::DragEventSourceInfo(),
  871                        RenderWidgetHostImpl::From(rvh()->GetWidget()));
  872  
  873    ui::OSExchangeData* exchange_data = drag_drop_client.GetDragDropData();
  874    EXPECT_FALSE(exchange_data);
  875  }
  876  
  877  // If the event location is not in the WebContentsViewAura, the drag will not be
  878  // started.
  879  TEST_F(WebContentsViewAuraTest, RejectDragFromOutsideView) {
  880    const char kGoogleUrl[] = "https://google.com/";
  881  
  882    std::u16string url_string = u"https://google.com/";
  883  
  884    NavigateAndCommit(GURL(kGoogleUrl));
  885  
  886    TestDragDropClient drag_drop_client;
  887    aura::client::SetDragDropClient(root_window(), &drag_drop_client);
  888  
  889    // Mark the Web Contents as native UI.
  890    WebContentsViewAura* view = GetView();
  891  
  892    const auto view_bounds_on_screen =
  893        view->GetContentNativeView()->GetBoundsInScreen();
  894  
  895    DropData drop_data;
  896    drop_data.url_infos = {ui::ClipboardUrlInfo{GURL(kGoogleUrl), u""}};
  897  
  898  #if BUILDFLAG(IS_CHROMEOS)
  899    // This condition is needed to avoid calling WebContentsViewAura::EndDrag
  900    // which will result NOTREACHED being called in
  901    // `RenderWidgetHostViewBase::TransformPointToCoordSpaceForView`.
  902    view->drag_in_progress_ = true;
  903  #endif  //  BUILDFLAG(IS_CHROMEOS)
  904  
  905    view->StartDragging(
  906        drop_data, url::Origin::Create(GURL(kGoogleUrl)),
  907        blink::DragOperationsMask::kDragOperationNone, gfx::ImageSkia(),
  908        gfx::Vector2d(), gfx::Rect(),
  909        blink::mojom::DragEventSourceInfo(
  910            {view_bounds_on_screen.x() + view_bounds_on_screen.width() + 1,
  911             view_bounds_on_screen.y() + 1},
  912            ui::mojom::DragEventSource::kMouse),
  913        RenderWidgetHostImpl::From(rvh()->GetWidget()));
  914  
  915    ui::OSExchangeData* exchange_data = drag_drop_client.GetDragDropData();
  916  #if BUILDFLAG(IS_CHROMEOS)
  917    // TODO(https://crbug.com/454552204): Remove #if when either ChromeOS
  918    // fixes split screen mode web ui tab strip drag, or web ui tab strip is
  919    // fully deprecated.
  920    EXPECT_TRUE(exchange_data);
  921  #else
  922    EXPECT_FALSE(exchange_data);
  923  #endif  //  BUILDFLAG(IS_CHROMEOS)
  924  }
  925  
  926  // Test that a drag from an event located outside the source view doesn't start.
  927  TEST_F(WebContentsViewAuraTest, EmptyTextInDropDataIsNonNullInOSExchangeData) {
  928    const char kGoogleUrl[] = "https://google.com/";
  929
```


#### 关键变更行

```diff
+ TEST_F(WebContentsViewAuraTest, RejectDragFromHiddenWebContents) {
+   const char kGoogleUrl[] = "https://google.com/";
+ 
+   std::u16string url_string = u"https://google.com/";
+ 
+   NavigateAndCommit(GURL(kGoogleUrl));
+ 
+   TestDragDropClient drag_drop_client;
+   aura::client::SetDragDropClient(root_window(), &drag_drop_client);
+ 
+   // Mark the Web Contents as native UI.
+   WebContentsViewAura* view = GetView();
+ 
+   DropData drop_data;
+   drop_data.url_infos = {ui::ClipboardUrlInfo{GURL(kGoogleUrl), u""}};
+ 
+   view->GetContentNativeView()->Hide();
+   view->StartDragging(drop_data, url::Origin::Create(GURL(kGoogleUrl)),
+                       blink::DragOperationsMask::kDragOperationNone,
+                       gfx::ImageSkia(), gfx::Vector2d(), gfx::Rect(),
+                       blink::mojom::DragEventSourceInfo(),
+                       RenderWidgetHostImpl::From(rvh()->GetWidget()));
+ 
+   ui::OSExchangeData* exchange_data = drag_drop_client.GetDragDropData();
+   EXPECT_FALSE(exchange_data);
+ }
+ 
+ // If the event location is not in the WebContentsViewAura, the drag will not be
+ // started.
+ TEST_F(WebContentsViewAuraTest, RejectDragFromOutsideView) {
+   const char kGoogleUrl[] = "https://google.com/";
+ 
+   std::u16string url_string = u"https://google.com/";
+ 
+   NavigateAndCommit(GURL(kGoogleUrl));
+ 
+   TestDragDropClient drag_drop_client;
+   aura::client::SetDragDropClient(root_window(), &drag_drop_client);
+ 
+   // Mark the Web Contents as native UI.
+   WebContentsViewAura* view = GetView();
+ 
+   const auto view_bounds_on_screen =
+       view->GetContentNativeView()->GetBoundsInScreen();
+ 
+   DropData drop_data;
+   drop_data.url_infos = {ui::ClipboardUrlInfo{GURL(kGoogleUrl), u""}};
+ 
+ #if BUILDFLAG(IS_CHROMEOS)
+   // This condition is needed to avoid calling WebContentsViewAura::EndDrag
+   // which will result NOTREACHED being called in
+   // `RenderWidgetHostViewBase::TransformPointToCoordSpaceForView`.
+   view->drag_in_progress_ = true;
+ #endif  //  BUILDFLAG(IS_CHROMEOS)
+ 
+   view->StartDragging(
+       drop_data, url::Origin::Create(GURL(kGoogleUrl)),
+       blink::DragOperationsMask::kDragOperationNone, gfx::ImageSkia(),
+       gfx::Vector2d(), gfx::Rect(),
+       blink::mojom::DragEventSourceInfo(
+           {view_bounds_on_screen.x() + view_bounds_on_screen.width() + 1,
+            view_bounds_on_screen.y() + 1},
+           ui::mojom::DragEventSource::kMouse),
+       RenderWidgetHostImpl::From(rvh()->GetWidget()));
+ 
+   ui::OSExchangeData* exchange_data = drag_drop_client.GetDragDropData();
+ #if BUILDFLAG(IS_CHROMEOS)
+   // TODO(https://crbug.com/454552204): Remove #if when either ChromeOS
+   // fixes split screen mode web ui tab strip drag, or web ui tab strip is
+   // fully deprecated.
+   EXPECT_TRUE(exchange_data);
+ #else
+   EXPECT_FALSE(exchange_data);
+ #endif  //  BUILDFLAG(IS_CHROMEOS)
+ }
+ 
+ // Test that a drag from an event located outside the source view doesn't start.
```


---

### 5. `TestRenderWidgetHostView::TestRenderWidgetHostView(RenderWidgetHost* rwh)`

**文件**：`content/test/test_render_view_host.cc`  |  **变更**：+2 / -0 行  |  ✅ 完整函数体（源文件已获取）

**Hunk 位置**：`@@ -77,10 +77,12 @@ TestRenderWidgetHostView::TestRenderWidgetHostView(RenderWidgetHost* rwh)`


#### 漏洞函数（修复前）

```cpp
namespace content {

TestRenderWidgetHostView::TestRenderWidgetHostView(RenderWidgetHost* rwh)
    : RenderWidgetHostViewBase(rwh),
      is_showing_(false),
      is_occluded_(false),
      cursor_manager_(this) {
#if BUILDFLAG(IS_ANDROID)
  frame_sink_id_ = AllocateFrameSinkId();
  GetHostFrameSinkManager()->RegisterFrameSinkId(
      frame_sink_id_, this, viz::ReportFirstSurfaceActivation::kYes);
#else
  default_background_color_ = SK_ColorWHITE;
  // Not all tests initialize or need an image transport factory.
  if (ImageTransportFactory::GetInstance()) {
    frame_sink_id_ = AllocateFrameSinkId();
    GetHostFrameSinkManager()->RegisterFrameSinkId(
        frame_sink_id_, this, viz::ReportFirstSurfaceActivation::kYes);
#if DCHECK_IS_ON()
    GetHostFrameSinkManager()->SetFrameSinkDebugLabel(
        frame_sink_id_, "TestRenderWidgetHostView");
#endif
  }
#endif

  host()->SetView(this);

  SetIsFrameSinkIdOwner(true);

#if defined(USE_AURA)
  window_ = std::make_unique<aura::Window>(
      aura::test::TestWindowDelegate::CreateSelfDestroyingDelegate());
  window_->set_owned_by_parent(false);
  window_->Init(ui::LayerType::LAYER_NOT_DRAWN);
#endif
}

TestRenderWidgetHostView::~TestRenderWidgetHostView() {
  viz::HostFrameSinkManager* manager = GetHostFrameSinkManager();
  if (manager)
    manager->InvalidateFrameSinkId(frame_sink_id_, this);
}

gfx::NativeView TestRenderWidgetHostView::GetNativeView() {
#if defined(USE_AURA)
  return window_.get();
#else
  return gfx::NativeView();
#endif
}

gfx::NativeViewAccessible TestRenderWidgetHostView::GetNativeViewAccessible() {
  return nullptr;
}

ui::TextInputClient* TestRenderWidgetHostView::GetTextInputClient() {
#if !BUILDFLAG(IS_IOS)
  return &text_input_client_;
#else
  NOTREACHED();
#endif
}

bool TestRenderWidgetHostView::HasFocus() {
  return true;
}

void TestRenderWidgetHostView::ShowWithVisibility(
    PageVisibilityState page_visibility) {
  page_visibility_ = page_visibility;
  OnShowWithPageVisibility(page_visibility_);
  is_showing_ = true;
  is_occluded_ = false;
}

void TestRenderWidgetHostView::Hide() {
  if (!host()->is_hidden())
    host()->WasHidden();
  is_showing_ = false;
}

bool TestRenderWidgetHostView::IsShowing() {
  return is_showing_;
}

void TestRenderWidgetHostView::WasUnOccluded() {
  // Can't be unoccluded unless the page is visible.
  page_visibility_ = PageVisibilityState::kVisible;
  OnShowWithPageVisibility(page_visibility_);
  is_occluded_ = false;
}

void TestRenderWidgetHostView::WasOccluded() {
  if (!host()->is_hidden())
    host()->WasHidden();
  is_occluded_ = true;
}

void TestRenderWidgetHostView::EnsureSurfaceSynchronizedForWebTest() {
  ++latest_capture_sequence_number_;
}

uint32_t TestRenderWidgetHostView::GetCaptureSequenceNumber() const {
  return latest_capture_sequence_number_;
}

void TestRenderWidgetHostView::UpdateCursor(const ui::Cursor& cursor) {
  last_cursor_ = cursor;
}

void TestRenderWidgetHostView::RenderProcessGone() {
  delete this;
}

void TestRenderWidgetHostView::Destroy() {
  // Call this here in case any observers need access to the `this` before
  // this derived class runs its destructor.
  NotifyObserversAboutShutdown();

  delete this;
}

gfx::Rect TestRenderWidgetHostView::GetViewBounds() {
  return gfx::Rect();
}

#if BUILDFLAG(IS_MAC)
void TestRenderWidgetHostView::SetActive(bool active) {
  // <viettrungluu@gmail.com>: Do I need to do anything here?
}

void TestRenderWidgetHostView::SpeakSelection() {
}

void TestRenderWidgetHostView::SetWindowFrameInScreen(const gfx::Rect& rect) {}

void TestRenderWidgetHostView::ShowSharePicker(
    const std::string& title,
    const std::string& text,
    const std::string& url,
    const std::vector<std::string>& file_paths,
    blink::mojom::ShareService::ShareCallback callback) {}

uint64_t TestRenderWidgetHostView::GetNSViewId() const {
  return 0;
}
#endif

gfx::Rect TestRenderWidgetHostView::GetBoundsInRootWindow() {
  return gfx::Rect();
}

const viz::LocalSurfaceId&
TestRenderWidgetHostView::IncrementSurfaceIdForNavigation() {
  static constexpr viz::LocalSurfaceId kInvalidId;
  return kInvalidId;
}

void TestRenderWidgetHostView::ClearFallbackSurfaceForCommitPending() {
  clear_fallback_surface_for_commit_pending_called_ = true;
}

void TestRenderWidgetHostView::TakeFallbackContentFrom(
    RenderWidgetHostView* view) {
  take_fallback_content_from_called_ = true;
  CopyBackgroundColorIfPresentFrom(*view);
}

blink::mojom::PointerLockResult TestRenderWidgetHostView::LockPointer(bool) {
  return blink::mojom::PointerLockResult::kUnknownError;
}

blink::mojom::PointerLockResult TestRenderWidgetHostView::ChangePointerLock(
    bool) {
  return blink::mojom::PointerLockResult::kUnknownError;
}

void TestRenderWidgetHostView::UnlockPointer() {}

const viz::FrameSinkId& TestRenderWidgetHostView::GetFrameSinkId() const {
  return frame_sink_id_;
}

const viz::LocalSurfaceId& TestRenderWidgetHostView::GetLocalSurfaceId() const {
  return viz::ParentLocalSurfaceIdAllocator::InvalidLocalSurfaceId();
}

viz::SurfaceId TestRenderWidgetHostView::GetCurrentSurfaceId() const {
  return viz::SurfaceId();
}

void TestRenderWidgetHostView::OnFirstSurfaceActivation(
    const viz::SurfaceInfo& surface_info) {
  // TODO(fsamuel): Once surface synchronization is turned on, the fallback
  // surface should be set here.
}

void TestRenderWidgetHostView::OnFrameTokenChanged(
    uint32_t frame_token,
    base::TimeTicks activation_time) {
  OnFrameTokenChangedForView(frame_token, activation_time);
}

void TestRenderWidgetHostView::ClearFallbackSurfaceCalled() {
  clear_fallback_surface_for_commit_pending_called_ = false;
  take_fallback_content_from_called_ = false;
}

std::unique_ptr<SyntheticGestureTarget>
TestRenderWidgetHostView::CreateSyntheticGestureTarget() {
  NOTIMPLEMENTED();
  return nullptr;
}

void TestRenderWidgetHostView::UpdateBackgroundColor() {}

void TestRenderWidgetHostView::SetDisplayFeatureForTesting(
    const DisplayFeature* display_feature) {
  if (display_feature)
    display_feature_ = *display_feature;
  else
    display_feature_ = std::nullopt;
}

void TestRenderWidgetHostView::NotifyHostAndDelegateOnWasShown(
    blink::mojom::RecordContentToVisibleTimeRequestPtr visible_time_request) {
  // Should only be called if the view was not already shown.
  EXPECT_TRUE(!is_showing_ || is_occluded_);
  switch (page_visibility_) {
    case PageVisibilityState::kVisible:
      // May or may not include a visible_time_request.
      break;
    case PageVisibilityState::kHiddenButPainting:
      EXPECT_FALSE(visible_time_request);
      break;
    case PageVisibilityState::kHidden:
      ADD_FAILURE();
      break;
  }
  if (host()->is_hidden()) {
    // Do not pass on `visible_time_request` because there is no compositing to
    // measure.
    host()->WasShown({});
  }
}

void TestRenderWidgetHostView::
    RequestSuccessfulPresentationTimeFromHostOrDelegate(
        blink::mojom::RecordContentToVisibleTimeRequestPtr
            visible_time_request) {
  // Should only be called if the view was already shown.
#if !BUILDFLAG(IS_ANDROID)
  // TODO(jonross): Update the constructor to determine showing state
  // `is_showing_ = !host()->is_hidden()` this will match production code. Also
  // update various tests not prepared for this to also match production.
  //
  // In tests TestRenderViewHostFactory::CreateRenderViewHost creates all hosts
  // as visible. Which leads to newly created views being attached to already
  // visible hosts. On Android we begin tracking content-to-visible-time when
  // recreating the main render frame. This leads to requests while already
  // visible in tests.
  EXPECT_TRUE(is_showing_);
#endif
  EXPECT_FALSE(is_occluded_);
  EXPECT_EQ(page_visibility_, PageVisibilityState::kVisible);
  EXPECT_TRUE(visible_time_request);
}

void TestRenderWidgetHostView::
    CancelSuccessfulPresentationTimeRequestForHostAndDelegate() {
  // Should only be called if the view was already shown.
  EXPECT_TRUE(is_showing_);
  EXPECT_FALSE(is_occluded_);
  EXPECT_EQ(page_visibility_, PageVisibilityState::kHiddenButPainting);
}

std::optional<DisplayFeature> TestRenderWidgetHostView::GetDisplayFeature() {
  return display_feature_;
}

ui::Compositor* TestRenderWidgetHostView::GetCompositor() {
  return compositor_;
}

input::CursorManager* TestRenderWidgetHostView::GetCursorManager() {
  return &cursor_manager_;
}

TestRenderWidgetHostViewChildFrame::TestRenderWidgetHostViewChildFrame(
    RenderWidgetHost* rwh)
    : RenderWidgetHostViewChildFrame(
          rwh,
          display::ScreenInfos(display::ScreenInfo())) {
  Init();
}

void TestRenderWidgetHostViewChildFrame::Reset() {
  last_gesture_seen_ = blink::WebInputEvent::Type::kUndefined;
}

void TestRenderWidgetHostViewChildFrame::SetCompositor(
    ui::Compositor* compositor) {
  compositor_ = compositor;
}

ui::Compositor* TestRenderWidgetHostViewChildFrame::GetCompositor() {
  return compositor_;
}

void TestRenderWidgetHostViewChildFrame::ProcessGestureEvent(
    const blink::WebGestureEvent& event,
    const ui::LatencyInfo&) {
  last_gesture_seen_ = event.GetType();
}

TestRenderViewHost::TestRenderViewHost(
    FrameTree* frame_tree,
    SiteInstanceGroup* group,
    const StoragePartitionConfig& storage_partition_config,
    std::unique_ptr<RenderWidgetHostImpl> widget,
    RenderViewHostDelegate* delegate,
    int32_t routing_id,
    int32_t main_frame_routing_id,
    scoped_refptr<BrowsingContextState> main_browsing_context_state,
    CreateRenderViewHostCase create_case)
    : RenderViewHostImpl(frame_tree,
                         group,
                         storage_partition_config,
                         std::move(widget),
                         delegate,
                         routing_id,
                         main_frame_routing_id,
                         false /* has_initialized_audio_host */,
                         std::move(main_browsing_context_state),
                         create_case),
      delete_counter_(nullptr) {
  if (frame_tree->is_fenced_frame()) {
    // TestRenderWidgetHostViewChildFrame deletes itself in
    // RenderWidgetHostViewChildFrame::Destroy.
    new TestRenderWidgetHostViewChildFrame(GetWidget());
  } else {
    // TestRenderWidgetHostView installs itself into this->view_ in
    // its constructor, and deletes itself when
    // TestRenderWidgetHostView::Destroy() is called.
    new TestRenderWidgetHostView(GetWidget());
  }
}

TestRenderViewHost::~TestRenderViewHost() {
  if (delete_counter_)
    ++*delete_counter_;
}

bool TestRenderViewHost::CreateTestRenderView() {
  return CreateRenderView(std::nullopt, MSG_ROUTING_NONE, false);
}

bool TestRenderViewHost::CreateRenderView(
    const std::optional<blink::FrameToken>& opener_frame_token,
    int proxy_route_id,
    bool window_was_created_with_opener) {
  DCHECK(!IsRenderViewLive());
  // Mark the `blink::WebView` as live, though there's nothing to do here since
  // we don't yet use mojo to talk to the RenderView.
  renderer_view_created_ = true;

  // When the RenderViewHost has a main frame host attached, the RenderView
  // in the renderer creates the main frame along with it. We mimic that here by
  // creating the mojo connections and calling RenderFrameCreated().
  RenderFrameHostImpl* main_frame = nullptr;
  RenderFrameProxyHost* proxy_host = nullptr;
  if (main_frame_routing_id_ != MSG_ROUTING_NONE) {
    main_frame = RenderFrameHostImpl::FromID(GetProcess()->GetID(),
                                             main_frame_routing_id_);
  } else {
    proxy_host =
        RenderFrameProxyHost::FromID(GetProcess()->GetID(), proxy_route_id);
  }

  if (!GetWidget()->view_is_frame_sink_id_owner()) {
    main_frame->NotifyWillCreateRenderWidgetOnCommit();
  }

  DCHECK_EQ(!!main_frame, is_active());
  if (main_frame) {
    // Pretend that we started a renderer process and created the renderer Frame
    // with its Widget. We bind all the mojom interfaces, but they all just talk
    // into the void.
    RenderWidgetHostImpl* main_frame_widget = main_frame->GetRenderWidgetHost();
    main_frame_widget->BindWidgetInterfaces(
        mojo::PendingAssociatedRemote<blink::mojom::WidgetHost>()
            .InitWithNewEndpointAndPassReceiver(),
        TestRenderWidgetHost::CreateStubWidgetRemote());
    main_frame_widget->BindFrameWidgetInterfaces(
        mojo::PendingAssociatedRemote<blink::mojom::FrameWidgetHost>()
            .InitWithNewEndpointAndPassReceiver(),
        TestRenderWidgetHost::CreateStubFrameWidgetRemote());
    main_frame->SetMojomFrameRemote(
        TestRenderFrameHost::CreateStubFrameRemote());

    // This also initializes the RenderWidgetHost attached to the frame.
    main_frame->RenderFrameCreated();
  } else {
    // Pretend that mojo connections of the RemoteFrame is transferred to
    // renderer process and bound in blink.
    mojo::AssociatedRemote<blink::mojom::RemoteFrame> remote_frame;
    std::ignore = remote_frame.BindNewEndpointAndPassDedicatedReceiver();
    proxy_host->BindRemoteFrameInterfaces(
        remote_frame.Unbind(),
        mojo::AssociatedRemote<blink::mojom::RemoteFrameHost>()
            .BindNewEndpointAndPassDedicatedReceiver());

    mojo::AssociatedRemote<blink::mojom::RemoteMainFrame> remote_main_frame;
    std::ignore = remote_main_frame.BindNewEndpointAndPassDedicatedReceiver();
    proxy_host->BindRemoteMainFrameInterfaces(
        remote_main_frame.Unbind(),
        mojo::AssociatedRemote<blink::mojom::RemoteMainFrameHost>()
            .BindNewEndpointAndPassDedicatedReceiver());

    proxy_host->SetRenderFrameProxyCreated(true);
  }

  mojo::AssociatedRemote<blink::mojom::PageBroadcast> broadcast_remote;
  page_broadcast_ = std::make_unique<TestPageBroadcast>(
      broadcast_remote.BindNewEndpointAndPassDedicatedReceiver());
  BindPageBroadcast(broadcast_remote.Unbind());

  opener_frame_token_ = opener_frame_token;
  DCHECK(IsRenderViewLive());
  return true;
}

MockRenderProcessHost* TestRenderViewHost::GetProcess() const {
  return static_cast<MockRenderProcessHost*>(RenderViewHostImpl::GetProcess());
}

void TestRenderViewHost::SimulateWasHidden() {
  GetWidget()->WasHidden();
}

void TestRenderViewHost::SimulateWasShown() {
  GetWidget()->WasShown({} /* record_tab_switch_time_request */);
}

blink::web_pref::WebPreferences
TestRenderViewHost::TestComputeWebPreferences() {
  return static_cast<WebContentsImpl*>(WebContents::FromRenderViewHost(this))
      ->ComputeWebPreferences();
}

bool TestRenderViewHost::IsTestRenderViewHost() const {
  return true;
}

void TestRenderViewHost::TestStartDragging(const DropData& drop_data,
                                           SkBitmap bitmap) {
  StoragePartitionImpl* storage_partition =
      static_cast<StoragePartitionImpl*>(GetProcess()->GetStoragePartition());
  GetMainRenderFrameHost()->StartDragging(
      DropDataToDragData(
          drop_data, storage_partition->GetFileSystemAccessManager(),
          GetProcess()->GetID(),
          ChromeBlobStorageContext::GetFor(GetProcess()->GetBrowserContext())),
      blink::kDragOperationEvery, std::move(bitmap), gfx::Vector2d(),
      gfx::Rect(), blink::mojom::DragEventSourceInfo::New());
}

void TestRenderViewHost::TestOnUpdateStateWithFile(
    const base::FilePath& file_path) {
  auto state = blink::PageState::CreateForTesting(GURL("http://www.google.com"),
                                                  false, "data", &file_path);
  GetMainRenderFrameHost()->UpdateState(state);
}

RenderViewHostImplTestHarness::RenderViewHostImplTestHarness()
    : RenderViewHostTestHarness(
          base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}

RenderViewHostImplTestHarness::~RenderViewHostImplTestHarness() = default;

TestRenderViewHost* RenderViewHostImplTestHarness::test_rvh() {
  return contents()->GetRenderViewHost();
}

TestRenderFrameHost* RenderViewHostImplTestHarness::main_test_rfh() {
  return contents()->GetPrimaryMainFrame();
}

TestWebContents* RenderViewHostImplTestHarness::contents() {
  return static_cast<TestWebContents*>(web_contents());
}

}  // namespace content
```


#### 修复函数（修复后）

```cpp
namespace content {

TestRenderWidgetHostView::TestRenderWidgetHostView(RenderWidgetHost* rwh)
    : RenderWidgetHostViewBase(rwh),
      is_showing_(false),
      is_occluded_(false),
      cursor_manager_(this) {
#if BUILDFLAG(IS_ANDROID)
  frame_sink_id_ = AllocateFrameSinkId();
  GetHostFrameSinkManager()->RegisterFrameSinkId(
      frame_sink_id_, this, viz::ReportFirstSurfaceActivation::kYes);
#else
  default_background_color_ = SK_ColorWHITE;
  // Not all tests initialize or need an image transport factory.
  if (ImageTransportFactory::GetInstance()) {
    frame_sink_id_ = AllocateFrameSinkId();
    GetHostFrameSinkManager()->RegisterFrameSinkId(
        frame_sink_id_, this, viz::ReportFirstSurfaceActivation::kYes);
#if DCHECK_IS_ON()
    GetHostFrameSinkManager()->SetFrameSinkDebugLabel(
        frame_sink_id_, "TestRenderWidgetHostView");
#endif
  }
#endif

  host()->SetView(this);

  SetIsFrameSinkIdOwner(true);

#if defined(USE_AURA)
  constexpr gfx::Rect kBounds = gfx::Rect(0, 0, 20, 20);
  window_ = std::make_unique<aura::Window>(
      aura::test::TestWindowDelegate::CreateSelfDestroyingDelegate());
  window_->set_owned_by_parent(false);
  window_->Init(ui::LayerType::LAYER_NOT_DRAWN);
  window_->SetBounds(kBounds);
#endif
}

TestRenderWidgetHostView::~TestRenderWidgetHostView() {
  viz::HostFrameSinkManager* manager = GetHostFrameSinkManager();
  if (manager)
    manager->InvalidateFrameSinkId(frame_sink_id_, this);
}

gfx::NativeView TestRenderWidgetHostView::GetNativeView() {
#if defined(USE_AURA)
  return window_.get();
#else
  return gfx::NativeView();
#endif
}

gfx::NativeViewAccessible TestRenderWidgetHostView::GetNativeViewAccessible() {
  return nullptr;
}

ui::TextInputClient* TestRenderWidgetHostView::GetTextInputClient() {
#if !BUILDFLAG(IS_IOS)
  return &text_input_client_;
#else
  NOTREACHED();
#endif
}

bool TestRenderWidgetHostView::HasFocus() {
  return true;
}

void TestRenderWidgetHostView::ShowWithVisibility(
    PageVisibilityState page_visibility) {
  page_visibility_ = page_visibility;
  OnShowWithPageVisibility(page_visibility_);
  is_showing_ = true;
  is_occluded_ = false;
}

void TestRenderWidgetHostView::Hide() {
  if (!host()->is_hidden())
    host()->WasHidden();
  is_showing_ = false;
}

bool TestRenderWidgetHostView::IsShowing() {
  return is_showing_;
}

void TestRenderWidgetHostView::WasUnOccluded() {
  // Can't be unoccluded unless the page is visible.
  page_visibility_ = PageVisibilityState::kVisible;
  OnShowWithPageVisibility(page_visibility_);
  is_occluded_ = false;
}

void TestRenderWidgetHostView::WasOccluded() {
  if (!host()->is_hidden())
    host()->WasHidden();
  is_occluded_ = true;
}

void TestRenderWidgetHostView::EnsureSurfaceSynchronizedForWebTest() {
  ++latest_capture_sequence_number_;
}

uint32_t TestRenderWidgetHostView::GetCaptureSequenceNumber() const {
  return latest_capture_sequence_number_;
}

void TestRenderWidgetHostView::UpdateCursor(const ui::Cursor& cursor) {
  last_cursor_ = cursor;
}

void TestRenderWidgetHostView::RenderProcessGone() {
  delete this;
}

void TestRenderWidgetHostView::Destroy() {
  // Call this here in case any observers need access to the `this` before
  // this derived class runs its destructor.
  NotifyObserversAboutShutdown();

  delete this;
}

gfx::Rect TestRenderWidgetHostView::GetViewBounds() {
  return gfx::Rect();
}

#if BUILDFLAG(IS_MAC)
void TestRenderWidgetHostView::SetActive(bool active) {
  // <viettrungluu@gmail.com>: Do I need to do anything here?
}

void TestRenderWidgetHostView::SpeakSelection() {
}

void TestRenderWidgetHostView::SetWindowFrameInScreen(const gfx::Rect& rect) {}

void TestRenderWidgetHostView::ShowSharePicker(
    const std::string& title,
    const std::string& text,
    const std::string& url,
    const std::vector<std::string>& file_paths,
    blink::mojom::ShareService::ShareCallback callback) {}

uint64_t TestRenderWidgetHostView::GetNSViewId() const {
  return 0;
}
#endif

gfx::Rect TestRenderWidgetHostView::GetBoundsInRootWindow() {
  return gfx::Rect();
}

const viz::LocalSurfaceId&
TestRenderWidgetHostView::IncrementSurfaceIdForNavigation() {
  static constexpr viz::LocalSurfaceId kInvalidId;
  return kInvalidId;
}

void TestRenderWidgetHostView::ClearFallbackSurfaceForCommitPending() {
  clear_fallback_surface_for_commit_pending_called_ = true;
}

void TestRenderWidgetHostView::TakeFallbackContentFrom(
    RenderWidgetHostView* view) {
  take_fallback_content_from_called_ = true;
  CopyBackgroundColorIfPresentFrom(*view);
}

blink::mojom::PointerLockResult TestRenderWidgetHostView::LockPointer(bool) {
  return blink::mojom::PointerLockResult::kUnknownError;
}

blink::mojom::PointerLockResult TestRenderWidgetHostView::ChangePointerLock(
    bool) {
  return blink::mojom::PointerLockResult::kUnknownError;
}

void TestRenderWidgetHostView::UnlockPointer() {}

const viz::FrameSinkId& TestRenderWidgetHostView::GetFrameSinkId() const {
  return frame_sink_id_;
}

const viz::LocalSurfaceId& TestRenderWidgetHostView::GetLocalSurfaceId() const {
  return viz::ParentLocalSurfaceIdAllocator::InvalidLocalSurfaceId();
}

viz::SurfaceId TestRenderWidgetHostView::GetCurrentSurfaceId() const {
  return viz::SurfaceId();
}

void TestRenderWidgetHostView::OnFirstSurfaceActivation(
    const viz::SurfaceInfo& surface_info) {
  // TODO(fsamuel): Once surface synchronization is turned on, the fallback
  // surface should be set here.
}

void TestRenderWidgetHostView::OnFrameTokenChanged(
    uint32_t frame_token,
    base::TimeTicks activation_time) {
  OnFrameTokenChangedForView(frame_token, activation_time);
}

void TestRenderWidgetHostView::ClearFallbackSurfaceCalled() {
  clear_fallback_surface_for_commit_pending_called_ = false;
  take_fallback_content_from_called_ = false;
}

std::unique_ptr<SyntheticGestureTarget>
TestRenderWidgetHostView::CreateSyntheticGestureTarget() {
  NOTIMPLEMENTED();
  return nullptr;
}

void TestRenderWidgetHostView::UpdateBackgroundColor() {}

void TestRenderWidgetHostView::SetDisplayFeatureForTesting(
    const DisplayFeature* display_feature) {
  if (display_feature)
    display_feature_ = *display_feature;
  else
    display_feature_ = std::nullopt;
}

void TestRenderWidgetHostView::NotifyHostAndDelegateOnWasShown(
    blink::mojom::RecordContentToVisibleTimeRequestPtr visible_time_request) {
  // Should only be called if the view was not already shown.
  EXPECT_TRUE(!is_showing_ || is_occluded_);
  switch (page_visibility_) {
    case PageVisibilityState::kVisible:
      // May or may not include a visible_time_request.
      break;
    case PageVisibilityState::kHiddenButPainting:
      EXPECT_FALSE(visible_time_request);
      break;
    case PageVisibilityState::kHidden:
      ADD_FAILURE();
      break;
  }
  if (host()->is_hidden()) {
    // Do not pass on `visible_time_request` because there is no compositing to
    // measure.
    host()->WasShown({});
  }
}

void TestRenderWidgetHostView::
    RequestSuccessfulPresentationTimeFromHostOrDelegate(
        blink::mojom::RecordContentToVisibleTimeRequestPtr
            visible_time_request) {
  // Should only be called if the view was already shown.
#if !BUILDFLAG(IS_ANDROID)
  // TODO(jonross): Update the constructor to determine showing state
  // `is_showing_ = !host()->is_hidden()` this will match production code. Also
  // update various tests not prepared for this to also match production.
  //
  // In tests TestRenderViewHostFactory::CreateRenderViewHost creates all hosts
  // as visible. Which leads to newly created views being attached to already
  // visible hosts. On Android we begin tracking content-to-visible-time when
  // recreating the main render frame. This leads to requests while already
  // visible in tests.
  EXPECT_TRUE(is_showing_);
#endif
  EXPECT_FALSE(is_occluded_);
  EXPECT_EQ(page_visibility_, PageVisibilityState::kVisible);
  EXPECT_TRUE(visible_time_request);
}

void TestRenderWidgetHostView::
    CancelSuccessfulPresentationTimeRequestForHostAndDelegate() {
  // Should only be called if the view was already shown.
  EXPECT_TRUE(is_showing_);
  EXPECT_FALSE(is_occluded_);
  EXPECT_EQ(page_visibility_, PageVisibilityState::kHiddenButPainting);
}

std::optional<DisplayFeature> TestRenderWidgetHostView::GetDisplayFeature() {
  return display_feature_;
}

ui::Compositor* TestRenderWidgetHostView::GetCompositor() {
  return compositor_;
}

input::CursorManager* TestRenderWidgetHostView::GetCursorManager() {
  return &cursor_manager_;
}

TestRenderWidgetHostViewChildFrame::TestRenderWidgetHostViewChildFrame(
    RenderWidgetHost* rwh)
    : RenderWidgetHostViewChildFrame(
          rwh,
          display::ScreenInfos(display::ScreenInfo())) {
  Init();
}

void TestRenderWidgetHostViewChildFrame::Reset() {
  last_gesture_seen_ = blink::WebInputEvent::Type::kUndefined;
}

void TestRenderWidgetHostViewChildFrame::SetCompositor(
    ui::Compositor* compositor) {
  compositor_ = compositor;
}

ui::Compositor* TestRenderWidgetHostViewChildFrame::GetCompositor() {
  return compositor_;
}

void TestRenderWidgetHostViewChildFrame::ProcessGestureEvent(
    const blink::WebGestureEvent& event,
    const ui::LatencyInfo&) {
  last_gesture_seen_ = event.GetType();
}

TestRenderViewHost::TestRenderViewHost(
    FrameTree* frame_tree,
    SiteInstanceGroup* group,
    const StoragePartitionConfig& storage_partition_config,
    std::unique_ptr<RenderWidgetHostImpl> widget,
    RenderViewHostDelegate* delegate,
    int32_t routing_id,
    int32_t main_frame_routing_id,
    scoped_refptr<BrowsingContextState> main_browsing_context_state,
    CreateRenderViewHostCase create_case)
    : RenderViewHostImpl(frame_tree,
                         group,
                         storage_partition_config,
                         std::move(widget),
                         delegate,
                         routing_id,
                         main_frame_routing_id,
                         false /* has_initialized_audio_host */,
                         std::move(main_browsing_context_state),
                         create_case),
      delete_counter_(nullptr) {
  if (frame_tree->is_fenced_frame()) {
    // TestRenderWidgetHostViewChildFrame deletes itself in
    // RenderWidgetHostViewChildFrame::Destroy.
    new TestRenderWidgetHostViewChildFrame(GetWidget());
  } else {
    // TestRenderWidgetHostView installs itself into this->view_ in
    // its constructor, and deletes itself when
    // TestRenderWidgetHostView::Destroy() is called.
    new TestRenderWidgetHostView(GetWidget());
  }
}

TestRenderViewHost::~TestRenderViewHost() {
  if (delete_counter_)
    ++*delete_counter_;
}

bool TestRenderViewHost::CreateTestRenderView() {
  return CreateRenderView(std::nullopt, MSG_ROUTING_NONE, false);
}

bool TestRenderViewHost::CreateRenderView(
    const std::optional<blink::FrameToken>& opener_frame_token,
    int proxy_route_id,
    bool window_was_created_with_opener) {
  DCHECK(!IsRenderViewLive());
  // Mark the `blink::WebView` as live, though there's nothing to do here since
  // we don't yet use mojo to talk to the RenderView.
  renderer_view_created_ = true;

  // When the RenderViewHost has a main frame host attached, the RenderView
  // in the renderer creates the main frame along with it. We mimic that here by
  // creating the mojo connections and calling RenderFrameCreated().
  RenderFrameHostImpl* main_frame = nullptr;
  RenderFrameProxyHost* proxy_host = nullptr;
  if (main_frame_routing_id_ != MSG_ROUTING_NONE) {
    main_frame = RenderFrameHostImpl::FromID(GetProcess()->GetID(),
                                             main_frame_routing_id_);
  } else {
    proxy_host =
        RenderFrameProxyHost::FromID(GetProcess()->GetID(), proxy_route_id);
  }

  if (!GetWidget()->view_is_frame_sink_id_owner()) {
    main_frame->NotifyWillCreateRenderWidgetOnCommit();
  }

  DCHECK_EQ(!!main_frame, is_active());
  if (main_frame) {
    // Pretend that we started a renderer process and created the renderer Frame
    // with its Widget. We bind all the mojom interfaces, but they all just talk
    // into the void.
    RenderWidgetHostImpl* main_frame_widget = main_frame->GetRenderWidgetHost();
    main_frame_widget->BindWidgetInterfaces(
        mojo::PendingAssociatedRemote<blink::mojom::WidgetHost>()
            .InitWithNewEndpointAndPassReceiver(),
        TestRenderWidgetHost::CreateStubWidgetRemote());
    main_frame_widget->BindFrameWidgetInterfaces(
        mojo::PendingAssociatedRemote<blink::mojom::FrameWidgetHost>()
            .InitWithNewEndpointAndPassReceiver(),
        TestRenderWidgetHost::CreateStubFrameWidgetRemote());
    main_frame->SetMojomFrameRemote(
        TestRenderFrameHost::CreateStubFrameRemote());

    // This also initializes the RenderWidgetHost attached to the frame.
    main_frame->RenderFrameCreated();
  } else {
    // Pretend that mojo connections of the RemoteFrame is transferred to
    // renderer process and bound in blink.
    mojo::AssociatedRemote<blink::mojom::RemoteFrame> remote_frame;
    std::ignore = remote_frame.BindNewEndpointAndPassDedicatedReceiver();
    proxy_host->BindRemoteFrameInterfaces(
        remote_frame.Unbind(),
        mojo::AssociatedRemote<blink::mojom::RemoteFrameHost>()
            .BindNewEndpointAndPassDedicatedReceiver());

    mojo::AssociatedRemote<blink::mojom::RemoteMainFrame> remote_main_frame;
    std::ignore = remote_main_frame.BindNewEndpointAndPassDedicatedReceiver();
    proxy_host->BindRemoteMainFrameInterfaces(
        remote_main_frame.Unbind(),
        mojo::AssociatedRemote<blink::mojom::RemoteMainFrameHost>()
            .BindNewEndpointAndPassDedicatedReceiver());

    proxy_host->SetRenderFrameProxyCreated(true);
  }

  mojo::AssociatedRemote<blink::mojom::PageBroadcast> broadcast_remote;
  page_broadcast_ = std::make_unique<TestPageBroadcast>(
      broadcast_remote.BindNewEndpointAndPassDedicatedReceiver());
  BindPageBroadcast(broadcast_remote.Unbind());

  opener_frame_token_ = opener_frame_token;
  DCHECK(IsRenderViewLive());
  return true;
}

MockRenderProcessHost* TestRenderViewHost::GetProcess() const {
  return static_cast<MockRenderProcessHost*>(RenderViewHostImpl::GetProcess());
}

void TestRenderViewHost::SimulateWasHidden() {
  GetWidget()->WasHidden();
}

void TestRenderViewHost::SimulateWasShown() {
  GetWidget()->WasShown({} /* record_tab_switch_time_request */);
}

blink::web_pref::WebPreferences
TestRenderViewHost::TestComputeWebPreferences() {
  return static_cast<WebContentsImpl*>(WebContents::FromRenderViewHost(this))
      ->ComputeWebPreferences();
}

bool TestRenderViewHost::IsTestRenderViewHost() const {
  return true;
}

void TestRenderViewHost::TestStartDragging(const DropData& drop_data,
                                           SkBitmap bitmap) {
  StoragePartitionImpl* storage_partition =
      static_cast<StoragePartitionImpl*>(GetProcess()->GetStoragePartition());
  GetMainRenderFrameHost()->StartDragging(
      DropDataToDragData(
          drop_data, storage_partition->GetFileSystemAccessManager(),
          GetProcess()->GetID(),
          ChromeBlobStorageContext::GetFor(GetProcess()->GetBrowserContext())),
      blink::kDragOperationEvery, std::move(bitmap), gfx::Vector2d(),
      gfx::Rect(), blink::mojom::DragEventSourceInfo::New());
}

void TestRenderViewHost::TestOnUpdateStateWithFile(
    const base::FilePath& file_path) {
  auto state = blink::PageState::CreateForTesting(GURL("http://www.google.com"),
                                                  false, "data", &file_path);
  GetMainRenderFrameHost()->UpdateState(state);
}

RenderViewHostImplTestHarness::RenderViewHostImplTestHarness()
    : RenderViewHostTestHarness(
          base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}

RenderViewHostImplTestHarness::~RenderViewHostImplTestHarness() = default;

TestRenderViewHost* RenderViewHostImplTestHarness::test_rvh() {
  return contents()->GetRenderViewHost();
}

TestRenderFrameHost* RenderViewHostImplTestHarness::main_test_rfh() {
  return contents()->GetPrimaryMainFrame();
}

TestWebContents* RenderViewHostImplTestHarness::contents() {
  return static_cast<TestWebContents*>(web_contents());
}

}  // namespace content
```


#### 关键变更行

```diff
+   constexpr gfx::Rect kBounds = gfx::Rect(0, 0, 20, 20);
+   window_->SetBounds(kBounds);
```


---

### 6. `（无函数名）`

**文件**：`ui/aura/env_input_state_controller.cc`  |  **变更**：+1 / -0 行  |  ⚠️ 仅 diff 上下文（源文件不可用，代码不完整）

**Hunk 位置**：`@@ -4,6 +4,7 @@`


#### 代码变更（diff 上下文，源文件不可用）

```diff
+ #include "build/build_config.h"
```

<details><summary>修复前上下文窗口（展开）</summary>

```cpp
/* patch context - source file unavailable */
/* ... line 4 ... */
    4  
    5  #include "ui/aura/env_input_state_controller.h"
    6  
    7  #include "ui/aura/client/screen_position_client.h"
    8  #include "ui/aura/env.h"
    9  #include "ui/events/event.h"
```

</details>

<details><summary>修复后上下文窗口（展开）</summary>

```cpp
/* patch context - source file unavailable */
/* ... line 4 ... */
    4  
    5  #include "ui/aura/env_input_state_controller.h"
    6  
    7  #include "build/build_config.h"
    8  #include "ui/aura/client/screen_position_client.h"
    9  #include "ui/aura/env.h"
   10  #include "ui/events/event.h"
```

</details>


---

### 7. `void EnvInputStateController::UpdateStateForTouchEvent(`

**文件**：`ui/aura/env_input_state_controller.cc`  |  **变更**：+8 / -2 行  |  ✅ 完整函数体（源文件已获取）

**Hunk 位置**：`@@ -48,11 +49,17 @@ void EnvInputStateController::UpdateStateForTouchEvent(`


#### 漏洞函数（修复前）

```cpp
void EnvInputStateController::UpdateStateForTouchEvent(
    const aura::Window* window,
    const ui::TouchEvent& event) {
  switch (event.type()) {
    case ui::EventType::kTouchPressed:
      touch_ids_down_ |= (1 << event.pointer_details().id);
      env_->SetTouchDown(touch_ids_down_ != 0);
      break;

    // Handle EventType::kTouchCancelled only if it has a native event.
    case ui::EventType::kTouchCancelled:
      if (!event.HasNativeEvent())
        break;
      [[fallthrough]];
    case ui::EventType::kTouchReleased:
      touch_ids_down_ = (touch_ids_down_ | (1 << event.pointer_details().id)) ^
                        (1 << event.pointer_details().id);
      env_->SetTouchDown(touch_ids_down_ != 0);
      break;

    case ui::EventType::kTouchMoved:
      break;

    default:
      NOTREACHED();
  }
  const gfx::Point& location_in_root = event.root_location();
  const auto* root_window = window->GetRootWindow();
  client::ScreenPositionClient* client =
      client::GetScreenPositionClient(root_window);
  gfx::Point location_in_screen = location_in_root;
  if (client) {
    client->ConvertPointToScreen(root_window, &location_in_screen);
  }
  env_->SetLastTouchLocation(window, location_in_screen);
}
```


#### 修复函数（修复后）

```cpp
void EnvInputStateController::UpdateStateForTouchEvent(
    const aura::Window* window,
    const ui::TouchEvent& event) {
  switch (event.type()) {
    case ui::EventType::kTouchPressed:
      touch_ids_down_ |= (1 << event.pointer_details().id);
      env_->SetTouchDown(touch_ids_down_ != 0);
      break;

    case ui::EventType::kTouchCancelled:
#if BUILDFLAG(IS_CHROMEOS)
      // Handle EventType::kTouchCancelled only if it has a native event.
      // ChromeOS exo touch drag relies on the ability to cancel touch
      // downs with synthetic events when handing off to the new consumer,
      // without losing the global env touch down state.
      if (!event.HasNativeEvent()) {
        break;
      }
      [[fallthrough]];
#endif  // BUILDFLAG(IS_CHROMEOS)
    case ui::EventType::kTouchReleased:
      touch_ids_down_ = (touch_ids_down_ | (1 << event.pointer_details().id)) ^
                        (1 << event.pointer_details().id);
      env_->SetTouchDown(touch_ids_down_ != 0);
      break;

    case ui::EventType::kTouchMoved:
      break;

    default:
      NOTREACHED();
  }
  const gfx::Point& location_in_root = event.root_location();
  const auto* root_window = window->GetRootWindow();
  client::ScreenPositionClient* client =
      client::GetScreenPositionClient(root_window);
  gfx::Point location_in_screen = location_in_root;
  if (client) {
    client->ConvertPointToScreen(root_window, &location_in_screen);
  }
  env_->SetLastTouchLocation(window, location_in_screen);
}
```


#### 关键变更行

```diff
-     // Handle EventType::kTouchCancelled only if it has a native event.
-       if (!event.HasNativeEvent())
+ #if BUILDFLAG(IS_CHROMEOS)
+       // Handle EventType::kTouchCancelled only if it has a native event.
+       // ChromeOS exo touch drag relies on the ability to cancel touch
+       // downs with synthetic events when handing off to the new consumer,
+       // without losing the global env touch down state.
+       if (!event.HasNativeEvent()) {
+       }
+ #endif  // BUILDFLAG(IS_CHROMEOS)
```


---

<a id="cve202510200"></a>

## CVE-2025-10200  ·  chromium_src  ·  高危

**参考链接**：<https://gitcode.com/openharmony-tpc/chromium_src/pull/4859>

**漏洞描述**：_（未获取到描述，可能需要 GITCODE_PRIVATE_TOKEN 或 GITHUB_TOKEN）_


共涉及 **2** 个函数／代码区域：

### 1. `void ServiceWorkerVersion::OnTimeoutTimer() {`

**文件**：`content/browser/service_worker/service_worker_version.cc`  |  **变更**：+21 / -20 行  |  ✅ 完整函数体（源文件已获取）

**Hunk 位置**：`@@ -2547,20 +2547,23 @@ void ServiceWorkerVersion::OnTimeoutTimer() {`、`@@ -2571,14 +2574,12 @@ void ServiceWorkerVersion::OnTimeoutTimer() {`


#### 漏洞函数（修复前）

```cpp
void ServiceWorkerVersion::OnTimeoutTimer() {
  // TODO(horo): This CHECK is for debugging crbug.com/759938.
  CHECK(running_status() == blink::EmbeddedWorkerStatus::kStarting ||
        running_status() == blink::EmbeddedWorkerStatus::kRunning ||
        running_status() == blink::EmbeddedWorkerStatus::kStopping)
      << static_cast<int>(running_status());

  if (!context_) {
    return;
  }

  MarkIfStale();

  // Global `this` protecter.
  // callbacks initiated by this function sometimes reduce refcnt to 0
  // to make this instance freed.
  scoped_refptr<ServiceWorkerVersion> protect_this(this);

  // Stopping the worker hasn't finished within a certain period.
  if (GetTickDuration(stop_time_) > kStopWorkerTimeout) {
    DCHECK_EQ(blink::EmbeddedWorkerStatus::kStopping, running_status());
    ReportError(blink::ServiceWorkerStatusCode::kErrorTimeout,
                "DETACH_STALLED_IN_STOPPING");

    embedded_worker_->RemoveObserver(this);
    embedded_worker_->Detach();
    embedded_worker_ = std::make_unique<EmbeddedWorkerInstance>(this);
    embedded_worker_->AddObserver(this);

    // Call OnStoppedInternal to fail callbacks and possibly restart.
    OnStoppedInternal(blink::EmbeddedWorkerStatus::kStopping);
    return;
  }

  // Trigger update if worker is stale and we waited long enough for it to go
  // idle.
  if (GetTickDuration(stale_time_) > kRequestTimeout) {
    ClearTick(&stale_time_);
    if (!update_timer_.IsRunning()) {
      ScheduleUpdate();
    }
  }

  // Starting a worker hasn't finished within a certain period.
  base::TimeDelta start_limit = IsInstalled(status())
                                    ? kStartInstalledWorkerTimeout
                                    : kStartNewWorkerTimeout;

  if (IsWarmedUp()) {
    start_limit =
        blink::features::kSpeculativeServiceWorkerWarmUpDuration.Get();
  }

  if (GetTickDuration(start_time_) > start_limit) {
    DCHECK(running_status() == blink::EmbeddedWorkerStatus::kStarting ||
           running_status() == blink::EmbeddedWorkerStatus::kStopping)
        << static_cast<int>(running_status());
    FinishStartWorker(blink::ServiceWorkerStatusCode::kErrorTimeout);
    if (running_status() == blink::EmbeddedWorkerStatus::kStarting) {
      embedded_worker_->Stop();
    }
    return;
  }

  // Are there requests that have not finished before their expiration.
  bool has_kill_on_timeout = false;
  bool has_continue_on_timeout = false;
  // In case, `request_timeouts_` can be modified in the callbacks initiated
  // in `MaybeTimeoutRequest`, we keep its contents locally during the
  // following while loop.
  std::set<InflightRequestTimeoutInfo> request_timeouts;
  request_timeouts.swap(request_timeouts_);
  auto timeout_iter = request_timeouts.begin();
  while (timeout_iter != request_timeouts.end()) {
    const InflightRequestTimeoutInfo& info = *timeout_iter;
    if (!RequestExpired(info.expiration_time)) {
      break;
    }
    if (MaybeTimeoutRequest(info)) {
      switch (info.timeout_behavior) {
        case KILL_ON_TIMEOUT:
          has_kill_on_timeout = true;
          break;
        case CONTINUE_ON_TIMEOUT:
          has_continue_on_timeout = true;
          break;
      }
    }
    timeout_iter = request_timeouts.erase(timeout_iter);
  }
  // Ensure the `request_timeouts_` won't be touched during the loop.
  DCHECK(request_timeouts_.empty());
  request_timeouts_.swap(request_timeouts);
  // TODO(crbug.com/40864997): remove the following DCHECK when the cause
  // identified.
  DCHECK_EQ(request_timeouts_.size(), inflight_requests_.size());

  if (has_kill_on_timeout &&
      running_status() != blink::EmbeddedWorkerStatus::kStopping) {
    embedded_worker_->Stop();
  }

  // For the timeouts below, there are no callbacks to timeout so there is
  // nothing more to do if the worker is already stopping.
  if (running_status() == blink::EmbeddedWorkerStatus::kStopping) {
    return;
  }

  // If an request is expired and there is no other requests, we ask event
  // queue to check if idle timeout should be scheduled. Event queue may
  // schedule idle timeout if there is no events at the time.
  if (has_continue_on_timeout && !HasWorkInBrowser()) {
    endpoint()->ClearKeepAlive();
  }

  // Check ping status.
  ping_controller_.CheckPingStatus();
}
```


#### 修复函数（修复后）

```cpp
void ServiceWorkerVersion::OnTimeoutTimer() {
  // TODO(horo): This CHECK is for debugging crbug.com/759938.
  CHECK(running_status() == blink::EmbeddedWorkerStatus::kStarting ||
        running_status() == blink::EmbeddedWorkerStatus::kRunning ||
        running_status() == blink::EmbeddedWorkerStatus::kStopping)
      << static_cast<int>(running_status());

  if (!context_) {
    return;
  }

  MarkIfStale();

  // Global `this` protecter.
  // callbacks initiated by this function sometimes reduce refcnt to 0
  // to make this instance freed.
  scoped_refptr<ServiceWorkerVersion> protect_this(this);

  // Stopping the worker hasn't finished within a certain period.
  if (GetTickDuration(stop_time_) > kStopWorkerTimeout) {
    DCHECK_EQ(blink::EmbeddedWorkerStatus::kStopping, running_status());
    ReportError(blink::ServiceWorkerStatusCode::kErrorTimeout,
                "DETACH_STALLED_IN_STOPPING");

    embedded_worker_->RemoveObserver(this);
    embedded_worker_->Detach();
    embedded_worker_ = std::make_unique<EmbeddedWorkerInstance>(this);
    embedded_worker_->AddObserver(this);

    // Call OnStoppedInternal to fail callbacks and possibly restart.
    OnStoppedInternal(blink::EmbeddedWorkerStatus::kStopping);
    return;
  }

  // Trigger update if worker is stale and we waited long enough for it to go
  // idle.
  if (GetTickDuration(stale_time_) > kRequestTimeout) {
    ClearTick(&stale_time_);
    if (!update_timer_.IsRunning()) {
      ScheduleUpdate();
    }
  }

  // Starting a worker hasn't finished within a certain period.
  base::TimeDelta start_limit = IsInstalled(status())
                                    ? kStartInstalledWorkerTimeout
                                    : kStartNewWorkerTimeout;

  if (IsWarmedUp()) {
    start_limit =
        blink::features::kSpeculativeServiceWorkerWarmUpDuration.Get();
  }

  if (GetTickDuration(start_time_) > start_limit) {
    DCHECK(running_status() == blink::EmbeddedWorkerStatus::kStarting ||
           running_status() == blink::EmbeddedWorkerStatus::kStopping)
        << static_cast<int>(running_status());
    FinishStartWorker(blink::ServiceWorkerStatusCode::kErrorTimeout);
    if (running_status() == blink::EmbeddedWorkerStatus::kStarting) {
      embedded_worker_->Stop();
    }
    return;
  }

  // 1. Identify timed-out requests and extract their info. This is done in a
  // separate loop to avoid race conditions where a timeout callback adds a new
  // request that could be immediately timed out.
  std::vector<InflightRequestTimeoutInfo> timed_out_infos;
  auto it = request_timeouts_.begin();
  while (it != request_timeouts_.end()) {
    if (!RequestExpired(it->expiration_time)) {
      break;
    }
    timed_out_infos.push_back(*it);
    it = request_timeouts_.erase(it);
  }

  // 2. Run the error callbacks for the timed-out requests.
  bool has_kill_on_timeout = false;
  bool has_continue_on_timeout = false;
  for (const auto& info : timed_out_infos) {
    if (MaybeTimeoutRequest(info)) {
      switch (info.timeout_behavior) {
        case KILL_ON_TIMEOUT:
          has_kill_on_timeout = true;
          break;
        case CONTINUE_ON_TIMEOUT:
          has_continue_on_timeout = true;
          break;
      }
    }
    }

  // TODO(crbug.com/40864997): This was promoted from a DCHECK to validate
  // the fix for this bug. If no crashes are observed by the next release
  // cycle, this CHECK and other related DCHECKs in this file can be removed.
  CHECK_EQ(request_timeouts_.size(), inflight_requests_.size());

  if (has_kill_on_timeout &&
      running_status() != blink::EmbeddedWorkerStatus::kStopping) {
    embedded_worker_->Stop();
  }

  // For the timeouts below, there are no callbacks to timeout so there is
  // nothing more to do if the worker is already stopping.
  if (running_status() == blink::EmbeddedWorkerStatus::kStopping) {
    return;
  }

  // If an request is expired and there is no other requests, we ask event
  // queue to check if idle timeout should be scheduled. Event queue may
  // schedule idle timeout if there is no events at the time.
  if (has_continue_on_timeout && !HasWorkInBrowser()) {
    endpoint()->ClearKeepAlive();
  }

  // Check ping status.
  ping_controller_.CheckPingStatus();
}
```


#### 关键变更行

```diff
-   // Are there requests that have not finished before their expiration.
-   bool has_kill_on_timeout = false;
-   bool has_continue_on_timeout = false;
-   // In case, `request_timeouts_` can be modified in the callbacks initiated
-   // in `MaybeTimeoutRequest`, we keep its contents locally during the
-   // following while loop.
-   std::set<InflightRequestTimeoutInfo> request_timeouts;
-   request_timeouts.swap(request_timeouts_);
-   auto timeout_iter = request_timeouts.begin();
-   while (timeout_iter != request_timeouts.end()) {
-     const InflightRequestTimeoutInfo& info = *timeout_iter;
-     if (!RequestExpired(info.expiration_time)) {
-     timeout_iter = request_timeouts.erase(timeout_iter);
-   }
-   // Ensure the `request_timeouts_` won't be touched during the loop.
-   DCHECK(request_timeouts_.empty());
-   request_timeouts_.swap(request_timeouts);
-   // TODO(crbug.com/40864997): remove the following DCHECK when the cause
-   // identified.
-   DCHECK_EQ(request_timeouts_.size(), inflight_requests_.size());
+   // 1. Identify timed-out requests and extract their info. This is done in a
+   // separate loop to avoid race conditions where a timeout callback adds a new
+   // request that could be immediately timed out.
+   std::vector<InflightRequestTimeoutInfo> timed_out_infos;
+   auto it = request_timeouts_.begin();
+   while (it != request_timeouts_.end()) {
+     if (!RequestExpired(it->expiration_time)) {
+     timed_out_infos.push_back(*it);
+     it = request_timeouts_.erase(it);
+   }
+ 
+   // 2. Run the error callbacks for the timed-out requests.
+   bool has_kill_on_timeout = false;
+   bool has_continue_on_timeout = false;
+   for (const auto& info : timed_out_infos) {
+     }
+ 
+   // TODO(crbug.com/40864997): This was promoted from a DCHECK to validate
+   // the fix for this bug. If no crashes are observed by the next release
+   // cycle, this CHECK and other related DCHECKs in this file can be removed.
+   CHECK_EQ(request_timeouts_.size(), inflight_requests_.size());
```


---

### 2. `bool ServiceWorkerVersion::MaybeTimeoutRequest(`

**文件**：`content/browser/service_worker/service_worker_version.cc`  |  **变更**：+12 / -2 行  |  ✅ 完整函数体（源文件已获取）

**Hunk 位置**：`@@ -2684,8 +2685,18 @@ bool ServiceWorkerVersion::MaybeTimeoutRequest(`


#### 漏洞函数（修复前）

```cpp
bool ServiceWorkerVersion::MaybeTimeoutRequest(
    const InflightRequestTimeoutInfo& info) {
  InflightRequest* request = inflight_requests_.Lookup(info.id);
  if (!request) {
    return false;
  }

  TRACE_EVENT_NESTABLE_ASYNC_END1("ServiceWorker",
                                  "ServiceWorkerVersion::Request",
                                  TRACE_ID_LOCAL(request), "Error", "Timeout");
  std::move(request->error_callback)
      .Run(blink::ServiceWorkerStatusCode::kErrorTimeout);
  inflight_requests_.Remove(info.id);
  return true;
}
```


#### 修复函数（修复后）

```cpp
bool ServiceWorkerVersion::MaybeTimeoutRequest(
    const InflightRequestTimeoutInfo& info) {
  InflightRequest* request = inflight_requests_.Lookup(info.id);
  if (!request) {
    return false;
  }

  TRACE_EVENT_NESTABLE_ASYNC_END1("ServiceWorker",
                                  "ServiceWorkerVersion::Request",
                                  TRACE_ID_LOCAL(request), "Error", "Timeout");

  // Move the callback to a local variable before removing the request from the
  // map, as the request object will be destroyed.
  auto error_callback = std::move(request->error_callback);

  // Remove the request from inflight_requests_ *before* running the callback.
  // This restores the invariant that request_timeouts_ and inflight_requests_
  // have the same size, preventing a DCHECK failure if the callback
  // synchronously finishes another request.
  inflight_requests_.Remove(info.id);

  std::move(error_callback).Run(blink::ServiceWorkerStatusCode::kErrorTimeout);
  inflight_requests_.Remove(info.id);
  return true;
}
```


#### 关键变更行

```diff
-   std::move(request->error_callback)
-       .Run(blink::ServiceWorkerStatusCode::kErrorTimeout);
+ 
+   // Move the callback to a local variable before removing the request from the
+   // map, as the request object will be destroyed.
+   auto error_callback = std::move(request->error_callback);
+ 
+   // Remove the request from inflight_requests_ *before* running the callback.
+   // This restores the invariant that request_timeouts_ and inflight_requests_
+   // have the same size, preventing a DCHECK failure if the callback
+   // synchronously finishes another request.
+   inflight_requests_.Remove(info.id);
+ 
+   std::move(error_callback).Run(blink::ServiceWorkerStatusCode::kErrorTimeout);
```


---

<a id="cve202250266"></a>

## CVE-2022-50266  ·  kernel_linux_5.10  ·  无

**参考链接**：<https://gitcode.com/openharmony/kernel_linux_5.10/commit/8ca9c1bb48293b47e69cb671afd0d8643dfe7679>

**标题**：kprobes: Fix check for probe enabled in kill_kprobe()

**漏洞描述**：

> mainline inclusion
> from mainline-v6.2-rc1
> commit 0c76ef3f26d5ef2ac2c21b47e7620cff35809fbb
> category: bugfix
> issue: #8134
> CVE: CVE-2022-50266
> ---------------------------------------
> In kill_kprobe(), the check whether disarm_kprobe_ftrace() needs to be
> called always fails. This is because before that we set the
> KPROBE_FLAG_GONE flag for kprobe so that "!kprobe_disabled(p)" is always
> false.
> The disarm_kprobe_ftrace() call introduced by commit:


共涉及 **1** 个函数／代码区域：

### 1. `static void kill_kprobe(struct kprobe *p)`

**文件**：`kernel/kprobes.c`  |  **变更**：+8 / -8 行  |  ✅ 完整函数体（源文件已获取）

**Hunk 位置**：`@@ -2285,6 +2285,14 @@ static void kill_kprobe(struct kprobe *p)`、`@@ -2301,14 +2309,6 @@ static void kill_kprobe(struct kprobe *p)`


#### 漏洞函数（修复前）

```c
static void kill_kprobe(struct kprobe *p)
{
	struct kprobe *kp;

	lockdep_assert_held(&kprobe_mutex);

	if (WARN_ON_ONCE(kprobe_gone(p)))
		return;

	p->flags |= KPROBE_FLAG_GONE;
	if (kprobe_aggrprobe(p)) {
		/*
		 * If this is an aggr_kprobe, we have to list all the
		 * chained probes and mark them GONE.
		 */
		list_for_each_entry(kp, &p->list, list)
			kp->flags |= KPROBE_FLAG_GONE;
		p->post_handler = NULL;
		kill_optimized_kprobe(p);
	}
	/*
	 * Here, we can remove insn_slot safely, because no thread calls
	 * the original probed function (which will be freed soon) any more.
	 */
	arch_remove_kprobe(p);

	/*
	 * The module is going away. We should disarm the kprobe which
	 * is using ftrace, because ftrace framework is still available at
	 * MODULE_STATE_GOING notification.
	 */
	if (kprobe_ftrace(p) && !kprobe_disabled(p) && !kprobes_all_disarmed)
		disarm_kprobe_ftrace(p);
}
```


#### 修复函数（修复后）

```c
static void kill_kprobe(struct kprobe *p)
{
	struct kprobe *kp;

	lockdep_assert_held(&kprobe_mutex);

	if (WARN_ON_ONCE(kprobe_gone(p)))
		return;

	/*
	 * The module is going away. We should disarm the kprobe which
	 * is using ftrace, because ftrace framework is still available at
	 * 'MODULE_STATE_GOING' notification.
	 */
	if (kprobe_ftrace(p) && !kprobe_disabled(p) && !kprobes_all_disarmed)
		disarm_kprobe_ftrace(p);

	p->flags |= KPROBE_FLAG_GONE;
	if (kprobe_aggrprobe(p)) {
		/*
		 * If this is an aggr_kprobe, we have to list all the
		 * chained probes and mark them GONE.
		 */
		list_for_each_entry(kp, &p->list, list)
			kp->flags |= KPROBE_FLAG_GONE;
		p->post_handler = NULL;
		kill_optimized_kprobe(p);
	}
	/*
	 * Here, we can remove insn_slot safely, because no thread calls
	 * the original probed function (which will be freed soon) any more.
	 */
	arch_remove_kprobe(p);
}
```


#### 关键变更行

```diff
- 
- 	/*
- 	 * The module is going away. We should disarm the kprobe which
- 	 * is using ftrace, because ftrace framework is still available at
- 	 * MODULE_STATE_GOING notification.
- 	 */
- 	if (kprobe_ftrace(p) && !kprobe_disabled(p) && !kprobes_all_disarmed)
- 		disarm_kprobe_ftrace(p);
+ 	/*
+ 	 * The module is going away. We should disarm the kprobe which
+ 	 * is using ftrace, because ftrace framework is still available at
+ 	 * 'MODULE_STATE_GOING' notification.
+ 	 */
+ 	if (kprobe_ftrace(p) && !kprobe_disabled(p) && !kprobes_all_disarmed)
+ 		disarm_kprobe_ftrace(p);
+ 
```


---
