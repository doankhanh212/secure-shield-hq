# 1. Tổng quan sản phẩm

Sản phẩm này là một bảng điều khiển bảo mật (SOC) cho đội vận hành. Người dùng có thể tạo lần quét bảo mật, theo dõi tiến trình quét, xem lỗ hổng, quản lý tài sản, và tải báo cáo sau quét. Mục tiêu chính là nhìn nhanh tình trạng rủi ro và xử lý lỗ hổng theo mức độ ưu tiên.

## Tech stack đang dùng

| Hạng mục | Công nghệ đang dùng |
|---|---|
| Framework | React 19 + TypeScript |
| UI library | shadcn/ui (dựa trên Radix UI) + Tailwind CSS |
| State management | TanStack Query cho dữ liệu server + React state cho UI cục bộ |
| API layer | src/services/api.ts (fetch wrapper tự viết) |
| Build tool | Vite |
| Routing | React Router |
| i18n | Hook useLanguage + từ điển trong src/lib/i18n.ts |
| Theme | Hook useTheme + localStorage |

## Cấu trúc thư mục src/

| Thư mục/File | Ý nghĩa |
|---|---|
| src/pages | Chứa các trang chính (Dashboard, Assets, Scans, Vulnerabilities, Reports, Settings, NotFound) |
| src/components/dashboard | Các widget hiển thị số liệu trên trang tổng quan |
| src/components/layout | Khung layout dùng chung: Sidebar + TopBar + DashboardLayout |
| src/components/scans | Component riêng cho luồng quét (ScanProgress) |
| src/components/ui | Bộ component nền tảng (button, input, dialog, table...) |
| src/components/NavLink.tsx | Wrapper NavLink để tái dùng class active/pending |
| src/hooks | Hook dùng chung: ngôn ngữ, theme, mobile, toast, dashboard data |
| src/lib/i18n.ts | Từ điển song ngữ vi/en |
| src/lib/utils.ts | Tiện ích dùng chung (đáng chú ý: cn để ghép class) |
| src/services/api.ts | Tất cả hàm gọi API |
| src/test | Setup test và ví dụ test |
| src/App.tsx | Khai báo router + provider toàn app |
| src/main.tsx | Entry mount React |
| src/index.css | Biến theme + global style |
| src/vite-env.d.ts | Khai báo kiểu cho Vite |

# 2. Sơ đồ các trang (Pages)

| Trang | Route | Mục đích | Component con chính | API calls | State cục bộ | React Query key | Vấn đề ghi nhận |
|---|---|---|---|---|---|---|---|
| Index.tsx | / | Trang tổng quan SOC, hiển thị KPI/charts/timeline | DashboardLayout, MetricCard, AttackSurfaceOverview, PostureChart, SeverityChart, ScanActivityTimeline, TopRiskAssets, RecentScans | Dùng qua hook useDashboardData: fetchScans, fetchVulnerabilities, fetchAssets, getAssets | now (thời gian để tính last updated), không có form state | ["dashboard-data"] | Còn text cứng tiếng Anh: Real-time security monitoring & threat analysis |
| AssetManagement.tsx | /assets | Quản lý tài sản, thêm/xóa tài sản, tìm kiếm tài sản | DashboardLayout, Dialog, Button, Input, Badge, Skeleton | getAssets, createAsset, deleteAsset | search, dialogOpen, newDomain, newIp, newCloud, newExposure | ["assets"] | Còn text cứng tiếng Anh: Loading..., assets monitored, Creating..., Add Asset, No assets discovered yet, No matching assets |
| SecurityScans.tsx | /scans | Tạo lần quét mới, xem danh sách và tiến trình quét đang chạy | DashboardLayout, Dialog, ScanProgress, Badge, Button, Skeleton | getScans, createScan, deleteScan (ScanProgress gọi getScan) | selectedMode, hasSelectedMode, target, dialogOpen | ["scans"], ["scan", scanId] ở component con | Còn text cứng tiếng Anh: Loading..., scans total, active, Start Scan, Starting..., Cancel, No scans yet...; mô tả mode đang hardcode |
| Vulnerabilities.tsx | /vulnerabilities | Danh sách lỗ hổng, filter mức độ, expand chi tiết, đánh dấu false positive | DashboardLayout, Input, Badge, Button, Skeleton | getVulnerabilities, patchVulnerability | expanded, search, severityFilter | ["vulnerabilities", severityFilter, search] | Đã cải thiện nhiều; còn một số cột và label đang trộn vi/en |
| Reports.tsx | /reports | Danh sách báo cáo, lọc/sắp xếp client-side, tải file report | DashboardLayout, Input, Badge, Button, Skeleton | getScans, getReports, getReportDownloadUrl | search, sortBy | ["scans"], ["reports", scanIds] | Còn title cứng tiếng Anh: Security Assessment — target; severity summary phụ thuộc dữ liệu backend mở rộng (⚠️ Cần xác nhận thêm) |
| Settings.tsx | /settings | Cấu hình giao diện và thông số hệ thống (hiện tại chủ yếu là UI mock) | DashboardLayout, Label, Input, Switch, Button | Không gọi API | Không có useState riêng | Không dùng React Query | Nhiều text cứng tiếng Anh: General, Platform Name, Scan Configuration, API Configuration; chưa có lưu cấu hình thật |
| NotFound.tsx | * | Trang 404 | Không dùng component layout | Không gọi API | Không có | Không có | Có console.error và text cứng tiếng Anh |

# 3. Sơ đồ các Component

## 3.1 Component nghiệp vụ (custom)

| File | Component | Props nhận vào | Dùng ở trang nào | Có dùng t() không | Ghi chú logic |
|---|---|---|---|---|---|
| src/components/NavLink.tsx | NavLink | className?: string, activeClassName?: string, pendingClassName?: string + NavLinkProps | Dùng trong layout/sidebar (gián tiếp) | Không | Wrapper mỏng cho router link |
| src/components/dashboard/MetricCard.tsx | MetricCard | title: string, value: string \| number, change?: string, changeType?: positive/negative/neutral, icon: LucideIcon, iconColor?: string, isLoading?: boolean, accentClassName?: string | Index.tsx | Không | Logic hiển thị skeleton + màu accent theo card |
| src/components/dashboard/PostureChart.tsx | PostureChart | data: {label: string; score: number}[], isLoading?: boolean | Index.tsx | Có | Tính diff score và render chart + empty state CTA |
| src/components/dashboard/RecentScans.tsx | RecentScans | scans: Scan[], isLoading?: boolean | Index.tsx | Có | Format thời gian tương đối, progress mini bar |
| src/components/dashboard/ScanActivityTimeline.tsx | ScanActivityTimeline | data: {day: string; scans: number; vulns: number}[], isLoading?: boolean | Index.tsx | Có | Dùng Recharts, có loading/empty |
| src/components/dashboard/SeverityChart.tsx | SeverityChart | critical/high/medium/low: number, isLoading?: boolean | Index.tsx | Có | Tính total + % + empty state "không có lỗ hổng" |
| src/components/dashboard/AttackSurfaceOverview.tsx | AttackSurfaceOverview | domains/subdomains/apis/ips/exposed: number, isLoading?: boolean | Index.tsx | Có | Box clickable điều hướng filter qua query string |
| src/components/dashboard/TopRiskAssets.tsx | TopRiskAssets | assets: {domain; score; criticals; highs}[], isLoading?: boolean | Index.tsx | Có | Tính màu theo score, card empty state |
| src/components/layout/AppSidebar.tsx | AppSidebar | Không có props | Tất cả trang qua DashboardLayout | Có | Logic active route, collapse sidebar |
| src/components/layout/DashboardLayout.tsx | DashboardLayout | children: ReactNode | Tất cả trang chính | Không | Khung chuẩn sidebar + topbar |
| src/components/layout/TopBar.tsx | TopBar | Không có props | Tất cả trang qua DashboardLayout | Có | Toggle theme + chuyển ngôn ngữ; còn số badge hardcode |
| src/components/scans/ScanProgress.tsx | ScanProgress | target: string, scanId?: string, scanMode?: string, startedAt?: string, stages?: ScanStage[] | SecurityScans.tsx | Có | Logic mapping stage, render timeline trạng thái, polling theo scanId |

## 3.2 Toàn bộ component trong src/components/ui (đủ file, không bỏ sót)

| File | Component export chính | Props | Dùng ở trang nào | Dùng t() | Ghi chú |
|---|---|---|---|---|---|
| src/components/ui/accordion.tsx | Accordion, AccordionItem, AccordionTrigger, AccordionContent | Theo Radix ComponentProps | Dùng chung nhiều nơi (chưa thấy dùng trực tiếp ở pages) | Không | Primitive UI |
| src/components/ui/alert-dialog.tsx | Nhóm AlertDialog* | Theo Radix ComponentProps | Dùng chung | Không | Primitive UI |
| src/components/ui/alert.tsx | Alert, AlertTitle, AlertDescription | className + variant | Dùng chung | Không | Primitive UI |
| src/components/ui/aspect-ratio.tsx | AspectRatio | Theo Radix | Dùng chung | Không | Primitive UI |
| src/components/ui/avatar.tsx | Avatar, AvatarImage, AvatarFallback | Theo Radix | Dùng chung | Không | Primitive UI |
| src/components/ui/badge.tsx | Badge, badgeVariants | BadgeProps | Nhiều trang: assets/scans/vulns/reports/dashboard | Không | Dùng rất nhiều |
| src/components/ui/breadcrumb.tsx | Nhóm Breadcrumb* | Theo Radix | Dùng chung | Không | Primitive UI |
| src/components/ui/button.tsx | Button, buttonVariants | ButtonProps | Nhiều trang | Không | Dùng rất nhiều |
| src/components/ui/calendar.tsx | Calendar | CalendarProps | Dùng chung | Không | Primitive UI |
| src/components/ui/card.tsx | Card, CardHeader, CardContent... | HTML div props | Dùng chung | Không | Primitive UI |
| src/components/ui/carousel.tsx | Carousel* | CarouselProps | Dùng chung | Không | Primitive UI |
| src/components/ui/chart.tsx | ChartContainer, ChartTooltip... | ChartConfig + props chart | Dùng chung (dashboard dùng Recharts trực tiếp) | Không | Có context chart |
| src/components/ui/checkbox.tsx | Checkbox | Theo Radix | Dùng chung | Không | Primitive UI |
| src/components/ui/collapsible.tsx | Collapsible* | Theo Radix | Dùng chung | Không | Primitive UI |
| src/components/ui/command.tsx | Command* | Theo cmdk + DialogProps | Dùng chung | Không | Primitive UI |
| src/components/ui/context-menu.tsx | ContextMenu* | Theo Radix | Dùng chung | Không | Primitive UI |
| src/components/ui/dialog.tsx | Dialog* | Theo Radix | Dùng pages assets/scans | Không | Dùng nhiều |
| src/components/ui/drawer.tsx | Drawer* | Theo Vaul/Radix | Dùng chung | Không | Primitive UI |
| src/components/ui/dropdown-menu.tsx | DropdownMenu* | Theo Radix | Dùng chung | Không | Primitive UI |
| src/components/ui/form.tsx | Form, FormField, FormItem... | react-hook-form wrappers | Dùng chung | Không | Primitive UI |
| src/components/ui/hover-card.tsx | HoverCard* | Theo Radix | Dùng chung | Không | Primitive UI |
| src/components/ui/input-otp.tsx | InputOTP* | Theo input-otp | Dùng chung | Không | Primitive UI |
| src/components/ui/input.tsx | Input | InputHTMLAttributes | Nhiều trang | Không | Dùng nhiều |
| src/components/ui/label.tsx | Label | LabelProps | Nhiều trang | Không | Dùng nhiều |
| src/components/ui/menubar.tsx | Menubar* | Theo Radix | Dùng chung | Không | Primitive UI |
| src/components/ui/navigation-menu.tsx | NavigationMenu* | Theo Radix | Dùng chung | Không | Primitive UI |
| src/components/ui/pagination.tsx | Pagination* | PaginationLinkProps | Dùng chung | Không | Primitive UI |
| src/components/ui/popover.tsx | Popover* | Theo Radix | Dùng chung | Không | Primitive UI |
| src/components/ui/progress.tsx | Progress | Theo Radix | Dùng chung | Không | Primitive UI |
| src/components/ui/radio-group.tsx | RadioGroup, RadioGroupItem | Theo Radix | Dùng chung | Không | Primitive UI |
| src/components/ui/resizable.tsx | ResizablePanelGroup, ResizablePanel, ResizableHandle | Theo react-resizable-panels | Dùng chung | Không | Primitive UI |
| src/components/ui/scroll-area.tsx | ScrollArea, ScrollBar | Theo Radix | Dùng chung | Không | Primitive UI |
| src/components/ui/select.tsx | Select* | Theo Radix | Dùng chung | Không | Primitive UI |
| src/components/ui/separator.tsx | Separator | Theo Radix | Dùng chung | Không | Primitive UI |
| src/components/ui/sheet.tsx | Sheet* | Theo Radix + variant | Dùng chung | Không | Primitive UI |
| src/components/ui/sidebar.tsx | Sidebar* | Sidebar props riêng | Dùng chung | Không | Primitive UI |
| src/components/ui/skeleton.tsx | Skeleton | className | Nhiều trang | Không | Dùng nhiều cho loading |
| src/components/ui/slider.tsx | Slider | Theo Radix | Dùng chung | Không | Primitive UI |
| src/components/ui/sonner.tsx | Toaster, toast | ToasterProps | Toàn app (App.tsx) | Không | Notification system |
| src/components/ui/switch.tsx | Switch | Theo Radix | Settings.tsx | Không | Primitive UI |
| src/components/ui/table.tsx | Table, TableHeader, TableRow... | HTML table props | Assets/Scans/Vulns (dùng table html trực tiếp nhiều hơn) | Không | Primitive UI |
| src/components/ui/tabs.tsx | Tabs* | Theo Radix | Dùng chung | Không | Primitive UI |
| src/components/ui/textarea.tsx | Textarea | TextareaHTMLAttributes | Dùng chung | Không | Primitive UI |
| src/components/ui/toast.tsx | Toast* | ToastProps | Toaster nội bộ | Không | Primitive UI |
| src/components/ui/toaster.tsx | Toaster | Không có props đáng kể | App.tsx | Không | Gắn UI toast |
| src/components/ui/toggle-group.tsx | ToggleGroup, ToggleGroupItem | Theo Radix | Dùng chung | Không | Primitive UI |
| src/components/ui/toggle.tsx | Toggle, toggleVariants | Theo Radix + variant | Dùng chung | Không | Primitive UI |
| src/components/ui/tooltip.tsx | Tooltip, TooltipTrigger, TooltipContent, TooltipProvider | Theo Radix | App.tsx bọc toàn app | Không | Primitive UI |
| src/components/ui/use-toast.ts | useToast, toast (re-export) | Không | Dùng chung | Không | Cầu nối sang hooks/use-toast |

⚠️ Cần xác nhận thêm: Một số primitive UI không được gọi trực tiếp ở pages, mà được dùng gián tiếp trong component khác hoặc chưa dùng ở phiên bản hiện tại.

# 4. API Layer

## Base URL

| Mục | Giá trị |
|---|---|
| API_BASE | /api/v1 |

## Danh sách hàm API

| Hàm | Method | Endpoint | Trả về | Có auth header? | Có xử lý lỗi? |
|---|---|---|---|---|---|
| getScans | GET | /api/v1/scans | Promise<Scan[]> | Không | Có, qua request() nếu status != ok |
| getScan | GET | /api/v1/scans/{scanId} | Promise<Scan> | Không | Có |
| createScan | POST | /api/v1/scans | Promise<{scan_id: string}> | Không | Có |
| deleteScan | DELETE | /api/v1/scans/{scanId} | Promise<{message: string}> | Không | Có |
| getAssets | GET | /api/v1/assets | Promise<Asset[]> | Không | Có |
| createAsset | POST | /api/v1/assets | Promise<Asset> | Không | Có |
| updateAsset | PUT | /api/v1/assets/{id} | Promise<Asset> | Không | Có |
| deleteAsset | DELETE | /api/v1/assets/{id} | Promise<{message: string}> | Không | Có |
| getAssetDiscovery | GET | /api/v1/assets/{scanId}/discovery | Promise<AssetDiscovery> | Không | Có |
| getVulnerabilities | GET | /api/v1/vulnerabilities?scan_id=&severity=&endpoint=&limit= | Promise<VulnerabilityResponse> | Không | Có |
| getVulnerability | GET | /api/v1/vulnerabilities/{id} | Promise<Vulnerability> | Không | Có |
| patchVulnerability | PATCH | /api/v1/vulnerabilities/{id} | Promise<Vulnerability> | Không | Có |
| getReports | GET | /api/v1/reports/{scanId} | Promise<ReportMeta> | Không | Có |
| getReportDownloadUrl | GET URL builder | /api/v1/reports/{scanId}/download?format= | string URL | Không | Không (chỉ tạo URL) |
| fetchScans (alias) | GET | /api/v1/scans | Promise<Scan[]> | Không | Có |
| fetchVulnerabilities (alias) | GET | /api/v1/vulnerabilities | Promise<VulnerabilityResponse> | Không | Có |
| fetchAssets (alias) | GET | /api/v1/assets/{scanId}/discovery | Promise<AssetDiscovery> | Không | Có |

## Nhận xét nhanh

| Nội dung | Kết luận |
|---|---|
| Error handling | Có mức cơ bản trong request(): throw Error("API {status}: {text}") |
| Auth header | Chưa có Authorization header |
| Retry/backoff | Chưa có |
| Hiển thị lỗi cho người dùng | Nhiều trang chưa hiển thị rõ (cần bổ sung toast/alert) |

# 5. Các kiểu dữ liệu quan trọng (Types)

| Type/Interface | Field chính | Dùng ở đâu |
|---|---|---|
| Lang | "vi" \| "en" | lib/i18n.ts, hook use-language.tsx, TopBar, Settings |
| Scan | scan_id, target, mode, status, stage, progress, created_at, error? | SecurityScans, RecentScans, use-dashboard-data, Reports |
| Vulnerability | id, scan_id, severity, endpoint, vulnerability_type, is_false_positive, explanation?, remediation?, status?, owasp_category?, cwe_id?, attack_vector?, poc?, ai_confidence?, remediation_note? | Vulnerabilities page, use-dashboard-data |
| VulnerabilityResponse | total, items[] | Vulnerabilities page, use-dashboard-data |
| Asset | id, domain, ip, cloud, status, exposure, open_ports[], technologies[], risk_score, created_at | AssetManagement, use-dashboard-data |
| AssetDiscovery | scan_id, target, domains[], subdomains[], services[], technologies[] | use-dashboard-data |
| ReportMeta | scan_id, target, scan_status, available_formats[], files | Reports page |
| DashboardData | nhóm KPI/charts/list + isLoading/isFetching/lastUpdatedAt/refresh | use-dashboard-data + Index page |
| LanguageContextType | lang, setLang, t | use-language hook/provider |
| ThemeContextType | theme, setTheme, toggleTheme | use-theme hook/provider |
| ScanStage (local) | key, icon, status, progress?, details? | component ScanProgress |
| SortOption (local) | newest \| oldest \| critical-first | Reports page |
| SeveritySummary (local) | critical?, high?, medium?, low? | Reports page |

# 6. Hệ thống dịch thuật (i18n)

## Cách useLanguage hoạt động

```tsx
// API public không đổi
return { t: (key: string) => tFn(key, lang), lang, setLang }
```

```tsx
// Mặc định tiếng Việt + lưu localStorage
const [lang, setLangState] = useState<Lang>(() =>
  (localStorage.getItem("lang") as Lang) ?? "vi"
)
```

```tsx
// setLang đã được bọc để tự lưu localStorage
const setLang = (l: Lang) => {
  setLangState(l)
  localStorage.setItem("lang", l)
}
```

## Ngôn ngữ mặc định

| Mục | Giá trị |
|---|---|
| Default language | vi (Tiếng Việt) |
| Persist | localStorage key: lang |

## Key còn thiếu do JSX hardcode (nên đưa vào i18n)

| File | Dòng | Text hardcode |
|---|---:|---|
| src/pages/Index.tsx | 39 | Real-time security monitoring & threat analysis |
| src/pages/AssetManagement.tsx | 88 | Loading... |
| src/pages/AssetManagement.tsx | 88 | assets monitored |
| src/pages/AssetManagement.tsx | 136 | Creating... |
| src/pages/AssetManagement.tsx | 136 | Add Asset |
| src/pages/AssetManagement.tsx | 166 | No assets discovered yet |
| src/pages/AssetManagement.tsx | 166 | No matching assets |
| src/pages/SecurityScans.tsx | 71 | Loading... |
| src/pages/SecurityScans.tsx | 71 | scans total • active |
| src/pages/SecurityScans.tsx | 133 | Starting... |
| src/pages/SecurityScans.tsx | 133 | Start Scan |
| src/pages/SecurityScans.tsx | 157 | Cancel |
| src/pages/SecurityScans.tsx | 190 | No scans yet — start your first scan above |
| src/pages/SecurityScans.tsx | 19-22 | Port scan + basic vuln check / OWASP Top 10 + CVE mapping / ... |
| src/pages/Reports.tsx | 234 | Security Assessment — |
| src/pages/Settings.tsx | 19 | General |
| src/pages/Settings.tsx | 22 | Platform Name |
| src/pages/Settings.tsx | 33 | Switch to English |
| src/pages/Settings.tsx | 40 | Scan Configuration |
| src/pages/Settings.tsx | 60 | API Configuration |
| src/pages/NotFound.tsx | 15 | Oops! Page not found |
| src/pages/NotFound.tsx | 17 | Return to Home |
| src/components/dashboard/RecentScans.tsx | 50 | No scans yet |
| src/components/dashboard/ScanActivityTimeline.tsx | 21 | No activity data |
| src/components/dashboard/ScanActivityTimeline.tsx | 49 | Scans |
| src/components/dashboard/ScanActivityTimeline.tsx | 53 | Vulns Found |
| src/components/dashboard/SeverityChart.tsx | 71 | Total |
| src/components/layout/AppSidebar.tsx | 47 | HQG Security |
| src/components/layout/AppSidebar.tsx | 50 | SOC Platform |
| src/components/layout/AppSidebar.tsx | 89 | System Online |
| src/components/scans/ScanProgress.tsx | 26-32 | stage label hardcode tiếng Việt (không qua t()) |

# 7. Routing

| Route | Page component | Public/Private | Ghi chú |
|---|---|---|---|
| / | Index | Public | Trang tổng quan |
| /assets | AssetManagement | Public | Quản lý tài sản |
| /scans | SecurityScans | Public | Quản lý lần quét |
| /vulnerabilities | Vulnerabilities | Public | Danh sách lỗ hổng |
| /reports | Reports | Public | Báo cáo |
| /settings | SettingsPage | Public | Cài đặt |
| * | NotFound | Public | Fallback 404 |

Kết luận hiện tại: chưa có route bắt buộc đăng nhập ở frontend.

# 8. Vấn đề cần chú ý

## A. LỖI TIỀM ẨN

| Nhóm | Kết quả |
|---|---|
| any không cần thiết | Không thấy dùng any tràn lan trong src (⚠️ Cần xác nhận thêm ở code generated từ thư viện) |
| console.log còn sót | Không thấy console.log; có 1 console.error ở NotFound |
| TODO/FIXME | Không thấy TODO/FIXME trong src |
| Hardcode URL | src/pages/Settings.tsx có https://api.hqg-security.local (UI mock) |
| Magic number | 30_000, 10_000, 5_000 (polling), limit 500/1000, MOBILE_BREAKPOINT=768, TOAST_LIMIT=1 |

## B. UX CÒN THIẾU

| Vấn đề | File chính |
|---|---|
| Nhiều trang chưa hiển thị lỗi API rõ ràng cho người dùng | AssetManagement, SecurityScans, Vulnerabilities, Reports |
| Form chưa có thông báo lỗi validation (chỉ disable button) | AssetManagement, SecurityScans |
| Settings chưa có save thật (mới mock UI) | Settings.tsx |
| Một số text loading/empty chưa đồng bộ i18n | nhiều file pages/components |
| TopBar có badge số hardcode (2,5) gây lệch dữ liệu thật | TopBar.tsx |

## C. TIẾNG ANH CÒN SÓT TRONG JSX

| File | Dòng | Text |
|---|---:|---|
| src/pages/Index.tsx | 39 | Real-time security monitoring & threat analysis |
| src/pages/AssetManagement.tsx | 88 | Loading... |
| src/pages/AssetManagement.tsx | 88 | assets monitored |
| src/pages/AssetManagement.tsx | 136 | Creating... |
| src/pages/AssetManagement.tsx | 136 | Add Asset |
| src/pages/AssetManagement.tsx | 166 | No assets discovered yet |
| src/pages/AssetManagement.tsx | 166 | No matching assets |
| src/pages/SecurityScans.tsx | 71 | Loading... |
| src/pages/SecurityScans.tsx | 71 | scans total • active |
| src/pages/SecurityScans.tsx | 133 | Starting... |
| src/pages/SecurityScans.tsx | 133 | Start Scan |
| src/pages/SecurityScans.tsx | 157 | Cancel |
| src/pages/SecurityScans.tsx | 190 | No scans yet — start your first scan above |
| src/pages/SecurityScans.tsx | 19-22 | Port scan + basic vuln check / OWASP Top 10 + CVE mapping / ... |
| src/pages/Reports.tsx | 234 | Security Assessment — |
| src/pages/Settings.tsx | 19 | General |
| src/pages/Settings.tsx | 22 | Platform Name |
| src/pages/Settings.tsx | 33 | Switch to English |
| src/pages/Settings.tsx | 40 | Scan Configuration |
| src/pages/Settings.tsx | 60 | API Configuration |
| src/pages/NotFound.tsx | 15 | Oops! Page not found |
| src/pages/NotFound.tsx | 17 | Return to Home |
| src/components/dashboard/RecentScans.tsx | 50 | No scans yet |
| src/components/dashboard/ScanActivityTimeline.tsx | 21 | No activity data |
| src/components/dashboard/ScanActivityTimeline.tsx | 49 | Scans |
| src/components/dashboard/ScanActivityTimeline.tsx | 53 | Vulns Found |
| src/components/dashboard/SeverityChart.tsx | 71 | Total |
| src/components/layout/AppSidebar.tsx | 47 | HQG Security |
| src/components/layout/AppSidebar.tsx | 50 | SOC Platform |
| src/components/layout/AppSidebar.tsx | 89 | System Online |

# 9. Những gì đã làm tốt

| Điểm tốt | Vì sao tốt |
|---|---|
| API tập trung trong 1 file services/api.ts | Dễ kiểm soát endpoint và chuẩn hóa lỗi |
| Dùng TanStack Query xuyên suốt | Tách rõ state server, tự refetch, dễ invalidate sau mutation |
| Dashboard gom data qua useDashboardData | Page gọn hơn, widget chỉ nhận dữ liệu đã xử lý |
| Có skeleton/loading ở nhiều nơi | Trải nghiệm mượt khi tải dữ liệu |
| Thiết kế component chia lớp rõ (pages/components/hooks/lib/services) | Dễ onboard và mở rộng |
| i18n đã có nền tảng tốt | Có provider riêng, key đã khá đầy đủ |
| Theme có lưu localStorage | Người dùng giữ được lựa chọn giao diện |

# 10. Việc cần làm tiếp theo (TODO)

## 🔴 Phải làm ngay (ảnh hưởng chức năng)

| Ưu tiên | Việc |
|---|---|
| 1 | Bổ sung hiển thị lỗi API cho người dùng (toast/alert) ở Assets/Scans/Vulns/Reports |
| 2 | Bỏ số hardcode ở TopBar (2 scanning, 5 notifications) và nối dữ liệu thật |
| 3 | Chuẩn hóa toàn bộ stage label trong ScanProgress sang t("scans.stage...") |

## 🟡 Nên làm sớm (ảnh hưởng UX)

| Ưu tiên | Việc |
|---|---|
| 1 | Đưa toàn bộ text hardcode còn sót vào i18n |
| 2 | Thêm thông báo validation cụ thể cho form tạo tài sản/tạo quét |
| 3 | Cập nhật Settings từ mock sang có lưu thật (hoặc ẩn bớt mục chưa dùng) |
| 4 | Chuẩn hóa ngôn ngữ trong toàn app (tránh trộn vi/en trong cùng màn hình) |

## 🟢 Có thể làm sau (polish)

| Ưu tiên | Việc |
|---|---|
| 1 | Rà lại magic number và gom vào hằng số cấu hình |
| 2 | Bổ sung test cho luồng chính (tạo scan, đánh dấu false positive, tải report) |
| 3 | Cải thiện empty state với CTA rõ hơn ở một số widget |
| 4 | Cân nhắc phân trang cho bảng lớn (vulns/assets/scans) |

---

## Tóm tắt số lượng

| Mục | Số lượng |
|---|---:|
| Số trang trong src/pages | 7 |
| Số file component trong src/components | 61 |
| Số vấn đề ghi nhận tổng | 40 |
| - Nhóm A (lỗi tiềm ẩn) | 8 |
| - Nhóm B (UX còn thiếu) | 5 |
| - Nhóm C (tiếng Anh còn sót) | 27 |

⚠️ Cần xác nhận thêm:
- Một số component UI primitive có thể chưa dùng trực tiếp ở pages nhưng được dùng gián tiếp.
- Dữ liệu severity summary ở Reports phụ thuộc backend; nếu backend chưa trả trường tương ứng thì hàng summary sẽ không hiện.
