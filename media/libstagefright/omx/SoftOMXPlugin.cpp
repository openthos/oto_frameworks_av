/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//#define LOG_NDEBUG 0
#define LOG_TAG "SoftOMXPlugin"
#include <utils/Log.h>

#include "SoftOMXPlugin.h"
#include "include/SoftOMXComponent.h"

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AString.h>

#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

namespace android {

static const struct {
    const char *mName;
    const char *mLibNameSuffix;
    const char *mRole;

} kComponents[] = {
    { "OMX.google.aac.decoder", "aacdec", "audio_decoder.aac" },
    { "OMX.google.aac.encoder", "aacenc", "audio_encoder.aac" },
    { "OMX.google.amrnb.decoder", "amrdec", "audio_decoder.amrnb" },
    { "OMX.google.amrnb.encoder", "amrnbenc", "audio_encoder.amrnb" },
    { "OMX.google.amrwb.decoder", "amrdec", "audio_decoder.amrwb" },
    { "OMX.google.amrwb.encoder", "amrwbenc", "audio_encoder.amrwb" },
    { "OMX.google.h264.decoder", NULL, "video_decoder.avc" },
    { "OMX.google.h264.encoder", "avcenc", "video_encoder.avc" },
    { "OMX.google.hevc.decoder", "hevcdec", "video_decoder.hevc" },
    { "OMX.google.g711.alaw.decoder", "g711dec", "audio_decoder.g711alaw" },
    { "OMX.google.g711.mlaw.decoder", "g711dec", "audio_decoder.g711mlaw" },
    { "OMX.google.mpeg2.decoder", "mpeg2dec", "video_decoder.mpeg2" },
    { "OMX.google.h263.decoder", "mpeg4dec", "video_decoder.h263" },
    { "OMX.google.h263.encoder", "mpeg4enc", "video_encoder.h263" },
    { "OMX.google.mpeg4.decoder", "mpeg4dec", "video_decoder.mpeg4" },
    { "OMX.google.mpeg4.encoder", "mpeg4enc", "video_encoder.mpeg4" },
    { "OMX.google.mp3.decoder", "mp3dec", "audio_decoder.mp3" },
    { "OMX.google.vorbis.decoder", "vorbisdec", "audio_decoder.vorbis" },
    { "OMX.google.opus.decoder", "opusdec", "audio_decoder.opus" },
    { "OMX.google.vp8.decoder", "vpxdec", "video_decoder.vp8" },
    { "OMX.google.vp9.decoder", "vpxdec", "video_decoder.vp9" },
    { "OMX.google.vp8.encoder", "vpxenc", "video_encoder.vp8" },
    { "OMX.google.raw.decoder", "rawdec", "audio_decoder.raw" },
    { "OMX.google.flac.encoder", "flacenc", "audio_encoder.flac" },
    { "OMX.google.gsm.decoder", "gsmdec", "audio_decoder.gsm" },
};

static const size_t kNumComponents =
    sizeof(kComponents) / sizeof(kComponents[0]);

SoftOMXPlugin::SoftOMXPlugin() {
}

static int isFennecProcess(int caller)
{
#define CMD_PATH_MAX       0x200
#define SHORT_LENGTH       0x20
#define TEMP_FILE_NAME_FMT "/mnt/tmp/media_%d"
#define PID_CMD_FMT "ps | awk '/org.mozilla.fennec_root|org.mozilla.firefox/{print $2}' > %s"

    int fd;
    int ret;
    pid_t pid;
    char buf[SHORT_LENGTH];
    char filename[SHORT_LENGTH];
    char cmd[CMD_PATH_MAX];

    sprintf(filename, TEMP_FILE_NAME_FMT, pid);
    sprintf(cmd, PID_CMD_FMT, filename);

    if (system(cmd)) {
        ALOGE("OPENTHOS: command failed: %s", cmd);
    }
    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        ALOGE("OPENTHOS: open file failed: %s", filename);
        return false;
    }
    ret = read(fd, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        ALOGE("OPENTHOS: read file failed: %s", filename);
        close(fd);
        return false;
    }
    buf[ret] = '\0';
    close(fd);

    sscanf(buf, "%d", &pid);
    return pid == caller;
}

OMX_ERRORTYPE SoftOMXPlugin::makeComponentInstance(
        const char *name,
        const OMX_CALLBACKTYPE *callbacks,
        OMX_PTR appData,
        OMX_COMPONENTTYPE **component,
        pid_t caller) {
    ALOGV("makeComponentInstance '%s'", name);

    for (size_t i = 0; i < kNumComponents; ++i) {
        if (strcmp(name, kComponents[i].mName)) {
            continue;
        }

        AString libName = "libstagefright_soft_";
        if (kComponents[i].mLibNameSuffix) {
            libName.append(kComponents[i].mLibNameSuffix);
        } else {
            libName.append(isFennecProcess(caller) ? "h264dec" : "avcdec");
        }
        libName.append(".so");

        void *libHandle = dlopen(libName.c_str(), RTLD_NOW);

        if (libHandle == NULL) {
            ALOGE("unable to dlopen %s: %s", libName.c_str(), dlerror());

            return OMX_ErrorComponentNotFound;
        }

        typedef SoftOMXComponent *(*CreateSoftOMXComponentFunc)(
                const char *, const OMX_CALLBACKTYPE *,
                OMX_PTR, OMX_COMPONENTTYPE **);

        CreateSoftOMXComponentFunc createSoftOMXComponent =
            (CreateSoftOMXComponentFunc)dlsym(
                    libHandle,
                    "_Z22createSoftOMXComponentPKcPK16OMX_CALLBACKTYPE"
                    "PvPP17OMX_COMPONENTTYPE");

        if (createSoftOMXComponent == NULL) {
            dlclose(libHandle);
            libHandle = NULL;

            return OMX_ErrorComponentNotFound;
        }

        sp<SoftOMXComponent> codec =
            (*createSoftOMXComponent)(name, callbacks, appData, component);

        if (codec == NULL) {
            dlclose(libHandle);
            libHandle = NULL;

            return OMX_ErrorInsufficientResources;
        }

        OMX_ERRORTYPE err = codec->initCheck();
        if (err != OMX_ErrorNone) {
            dlclose(libHandle);
            libHandle = NULL;

            return err;
        }

        codec->incStrong(this);
        codec->setLibHandle(libHandle);

        return OMX_ErrorNone;
    }

    return OMX_ErrorInvalidComponentName;
}

OMX_ERRORTYPE SoftOMXPlugin::destroyComponentInstance(
        OMX_COMPONENTTYPE *component) {
    SoftOMXComponent *me =
        (SoftOMXComponent *)
            ((OMX_COMPONENTTYPE *)component)->pComponentPrivate;

    me->prepareForDestruction();

    void *libHandle = me->libHandle();

    CHECK_EQ(me->getStrongCount(), 1);
    me->decStrong(this);
    me = NULL;

    dlclose(libHandle);
    libHandle = NULL;

    return OMX_ErrorNone;
}

OMX_ERRORTYPE SoftOMXPlugin::enumerateComponents(
        OMX_STRING name,
        size_t /* size */,
        OMX_U32 index) {
    if (index >= kNumComponents) {
        return OMX_ErrorNoMore;
    }

    strcpy(name, kComponents[index].mName);

    return OMX_ErrorNone;
}

OMX_ERRORTYPE SoftOMXPlugin::getRolesOfComponent(
        const char *name,
        Vector<String8> *roles) {
    for (size_t i = 0; i < kNumComponents; ++i) {
        if (strcmp(name, kComponents[i].mName)) {
            continue;
        }

        roles->clear();
        roles->push(String8(kComponents[i].mRole));

        return OMX_ErrorNone;
    }

    return OMX_ErrorInvalidComponentName;
}

}  // namespace android
