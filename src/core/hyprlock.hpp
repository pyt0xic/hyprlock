#pragma once

#include <wayland-client.h>
#include "ext-session-lock-v1-protocol.h"
#include "fractional-scale-v1-protocol.h"
#include "linux-dmabuf-unstable-v1-protocol.h"
#include "wlr-screencopy-unstable-v1-protocol.h"
#include "viewporter-protocol.h"
#include "Output.hpp"
#include "CursorShape.hpp"
#include "Timer.hpp"
#include "Password.hpp"

#include <memory>
#include <vector>
#include <condition_variable>
#include <optional>

#include <xkbcommon/xkbcommon.h>

#include <gbm.h>
#include <xf86drm.h>

struct SDMABUFModifier {
    uint32_t fourcc = 0;
    uint64_t mod    = 0;
};

class CHyprlock {
  public:
    CHyprlock(const std::string& wlDisplay);

    void                            run();

    void                            onGlobal(void* data, struct wl_registry* registry, uint32_t name, const char* interface, uint32_t version);
    void                            onGlobalRemoved(void* data, struct wl_registry* registry, uint32_t name);

    std::shared_ptr<CTimer>         addTimer(const std::chrono::system_clock::duration& timeout, std::function<void(std::shared_ptr<CTimer> self, void* data)> cb_, void* data);

    void                            onLockLocked();
    void                            onLockFinished();

    void                            lockSession();
    void                            unlockSession();

    void                            spawnAsync(const std::string& cmd);
    std::string                     spawnSync(const std::string& cmd);

    void                            onKey(uint32_t key, bool down);
    void                            onPasswordCheckTimer();
    bool                            passwordCheckWaiting();
    std::optional<std::string>      passwordLastFailReason();

    size_t                          getPasswordBufferLen();

    ext_session_lock_manager_v1*    getSessionLockMgr();
    ext_session_lock_v1*            getSessionLock();
    wl_compositor*                  getCompositor();
    wl_display*                     getDisplay();
    wp_fractional_scale_manager_v1* getFractionalMgr();
    wp_viewporter*                  getViewporter();
    zwlr_screencopy_manager_v1*     getScreencopy();

    wl_pointer*                     m_pPointer = nullptr;
    wl_keyboard*                    m_pKeeb    = nullptr;

    std::unique_ptr<CCursorShape>   m_pCursorShape;

    xkb_context*                    m_pXKBContext = nullptr;
    xkb_keymap*                     m_pXKBKeymap  = nullptr;
    xkb_state*                      m_pXKBState   = nullptr;

    bool                            m_bTerminate = false;

    bool                            m_bLocked = false;

    //
    std::chrono::system_clock::time_point m_tGraceEnds;
    Vector2D                              m_vLastEnterCoords = {};

    std::vector<std::unique_ptr<COutput>> m_vOutputs;

    struct {
        void*                        linuxDmabuf         = nullptr;
        void*                        linuxDmabufFeedback = nullptr;

        gbm_bo*                      gbm       = nullptr;
        gbm_device*                  gbmDevice = nullptr;

        void*                        formatTable     = nullptr;
        size_t                       formatTableSize = 0;
        bool                         deviceUsed      = false;

        std::vector<SDMABUFModifier> dmabufMods;
    } dma;
    gbm_device* createGBMDevice(drmDevice* dev);

  private:
    struct {
        wl_display*                     display     = nullptr;
        wl_registry*                    registry    = nullptr;
        wl_seat*                        seat        = nullptr;
        ext_session_lock_manager_v1*    sessionLock = nullptr;
        wl_compositor*                  compositor  = nullptr;
        wp_fractional_scale_manager_v1* fractional  = nullptr;
        wp_viewporter*                  viewporter  = nullptr;
        zwlr_screencopy_manager_v1*     screencopy  = nullptr;
    } m_sWaylandState;

    struct {
        ext_session_lock_v1* lock = nullptr;
    } m_sLockState;

    struct {
        std::string                                     passBuffer = "";
        std::shared_ptr<CPassword::SVerificationResult> result;
        std::optional<std::string>                      lastFailReason;
    } m_sPasswordState;

    struct {
        std::mutex              timersMutex;
        std::mutex              eventRequestMutex;
        std::mutex              eventLoopMutex;
        std::condition_variable loopCV;
        bool                    event = false;

        std::condition_variable timerCV;
        std::mutex              timerRequestMutex;
        bool                    timerEvent = false;
    } m_sLoopState;

    std::vector<std::shared_ptr<CTimer>> m_vTimers;

    std::vector<uint32_t>                m_vPressedKeys;
};

inline std::unique_ptr<CHyprlock> g_pHyprlock;