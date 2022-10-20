from django.conf.urls import include, url
from django.contrib import admin

from django.http import HttpResponseRedirect
from . import views

urlpatterns = [
    #url(r'^$', lambda r: HttpResponseRedirect('workspaces')),
    
    url(r'^$', views.home, name = 'home'),
    url(r'^disclaimer$', views.disclaimer, name = 'disclaimer'),
    url(r'^disclaimer/accept$', views.accept_disclaimer, name = 'accept_disclaimer'),

    url(r'^coastal$', views.home_coastal, name = 'home_coastal'),
    url(r'^inland$', views.home_inland, name = 'home_inland'),
    url(r'^waterleak$', views.home_waterleak, name = 'home_waterleak'),

    url(r'^users/(?P<user_id>[0-9]+)$', views.get_user, name = 'get_user'),

    url(r'^rois$', views.regions_of_interest, name = 'regions_of_interest'),
    url(r'^rois/(?P<roi_id>[0-9]+)$', views.get_region_of_interest, name = 'get_region_of_interest'),
    url(r'^rois/create$', views.create_region_of_interest, name = 'create_region_of_interest'),
    url(r'^rois/(?P<roi_id>[0-9]+)/delete_roi$', views.delete_region_of_interest, name = 'delete_region_of_interest'),
    url(r'^upload_roi_coords$', views.upload_roi_coords, name='upload_roi_coords'),
    

    #old interface
    url(r'^rois/(?P<roi_id>[0-9]+)/create_simulation$', views.create_simulation, name = 'create_simulation'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations$', views.get_simulations, name = 'get_simulations'),
    url(r'^rois/(?P<roi_id>[0-9]+)/waterleak_check_existing_simulation$', views.waterleak_check_existing_simulation, name = 'waterleak_check_existing_simulation'),    
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)$', views.show_simulation, name = 'show_simulation'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/details$', views.show_simulation_details, name = 'show_simulation_details'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/show_blob$', views.load_json_blob_simulation, name = 'load_json_blob_simulation'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/run_simulation$', views.run_simulation, name = 'run_simulation'),    
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/restart_simulation$', views.restart_simulation, name = 'restart_simulation'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/update_simulation$', views.update_simulation, name = 'update_simulation'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/stop_simulation$', views.stop_simulation, name = 'stop_simulation'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/show_simulation$', views.show_simulation, name = 'show_simulation'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/delete_simulation$', views.delete_simulation, name = 'delete_simulation'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/edit_simulation$', views.edit_simulation, name = 'edit_simulation'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/share_with$', views.get_user_share_simulation, name = 'get_user_share_simulation'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/share_with/new_user$', views.add_user_share_simulation, name = 'add_user_share_simulation'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/share_with/(?P<existing_user_id>[0-9]+)/remove$', views.remove_user_share_simulation, name = 'remove_user_share_simulation'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/intermediate/clone_cleanup_all$', views.clone_cleanup_simulation_coastlines, name = 'clone_cleanup_simulation_coastlines'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/intermediate/processimageset/(?P<intermediate_process_imageset_id>[0-9]+)/coastline/(?P<shp_mpis_id>[0-9]+)$', views.show_simulation_procimageset_coastline, name = 'show_simulation_procimageset_coastline'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/intermediate/processimageset/(?P<intermediate_process_imageset_id>[0-9]+)/coastline/(?P<shp_mpis_id>[0-9]+)/clone_cleanup$', views.clone_cleanup_simulation_procimageset_coastline, name = 'clone_cleanup_simulation_procimageset_coastline'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/intermediate/processimageset/(?P<intermediate_process_imageset_id>[0-9]+)/coastline/(?P<shp_mpis_id>[0-9]+)/delete_cleanup$', views.delete_cleanup_simulation_procimageset_coastline, name = 'delete_cleanup_simulation_procimageset_coastline'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/intermediate/processimageset/(?P<intermediate_process_imageset_id>[0-9]+)/coastline/(?P<shp_mpis_id>[0-9]+)/download_cleanup$', views.download_cleanup_simulation_procimageset_coastline, name = 'download_cleanup_simulation_procimageset_coastline'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/intermediate/processimageset/(?P<intermediate_process_imageset_id>[0-9]+)/download_products$', views.proxy_get_intermediate_download_simulation_products, name = 'proxy_get_intermediate_download_simulation_products'),
    #url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/intermediate/processimageset/(?P<intermediate_process_imageset_id>[0-9]+)/(?P<determine_leak_by>[\w+]+)/run_leak_detection$', views.run_leak_detection, name = 'run_leak_detection'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/intermediate/averageprocessimageset/(?P<intermediate_process_imageset_id>[0-9]+)/download_products$', views.proxy_get_intermediate_download_simulation_products_climatology, name = 'proxy_get_intermediate_download_simulation_products_climatology'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/intermediate/processimageset/(?P<intermediate_process_imageset_id>[0-9]+)/(?P<intermediate_raster_type>[\w+]+)/create_threshold$', views.create_threshold_simulation_procimageset, name = 'create_threshold_simulation_procimageset'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/intermediate/processimageset/(?P<intermediate_process_imageset_id>[0-9]+)/(?P<intermediate_raster_type>[\w+]+)/download_threshold$', views.download_threshold_simulation_procimageset, name = 'download_threshold_simulation_procimageset'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/intermediate/processimageset/(?P<intermediate_process_imageset_id>[0-9]+)/(?P<intermediate_raster_type>[\w+]+)/(?P<intermediate_raster_id>[0-9]+)$', views.show_simulation_procimageset_raster, name = 'show_simulation_procimageset_raster'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/intermediate/processimageset/(?P<intermediate_process_imageset_id>[0-9]+)/(?P<intermediate_raster_type>[\w+]+)/(?P<intermediate_raster_id>[0-9]+)/show_histogram$', views.show_simulation_procimageset_raster_histogram, name = 'show_simulation_procimageset_raster_histogram'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/intermediate/averageprocessimageset/(?P<intermediate_process_imageset_id>[0-9]+)/(?P<intermediate_raster_type>[\w+]+)/(?P<intermediate_raster_id>[0-9]+)$', views.show_simulation_procimageset_raster_climatology, name = 'show_simulation_procimageset_raster_climatology'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/intermediate/generatetopography/(?P<intermediate_gt_id>[0-9]+)/(?P<intermediate_raster_type>[\w+]+)/(?P<intermediate_raster_id>[0-9]+)$', views.show_simulation_topography_raster, name = 'show_simulation_topography_raster'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/intermediate/generatetopography/(?P<intermediate_gt_id>[0-9]+)/download_products$', views.proxy_get_intermediate_download_topography, name = 'proxy_get_intermediate_download_topography'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/intermediate/generatetopography/(?P<intermediate_gt_id>[0-9]+)/delete_products$', views.proxy_get_intermediate_delete_topography, name = 'proxy_get_intermediate_delete_topography'),

    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/dataverses$', views.get_simulation_dataverse_datasets, name = 'get_simulation_dataverse_datasets'),
    url(r'^rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/dataverses/submit$', views.add_simulation_dataverse_datasets, name = 'add_simulation_dataverse_datasets'),
    
    #
    url(r'^waterleak/leakdetection/rois$', views.waterleak_get_list_rois, name = 'waterleak_get_list_rois'),
    url(r'^waterleak/leakdetection/leak_detections$', views.waterleak_get_all_leak_detections, name = 'waterleak_get_all_leak_detections'),
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/compatible_pipe_networks$', views.waterleak_get_compatible_pipe_networks, name = 'waterleak_get_compatible_pipe_networks'),
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations$', views.waterleak_get_list_simulations, name = 'waterleak_get_list_simulations'),
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/create_leak_detection$', views.waterleak_create_leak_detection, name = 'waterleak_create_leak_detection'),
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/leak_detections$', views.waterleak_get_leak_detections, name = 'waterleak_get_leak_detections'),
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/leak_detections/(?P<leak_detection_id>[0-9]+)$', views.waterleak_get_leak_detection_details, name = 'waterleak_get_leak_detection_details'),
    #url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/leak_detections/(?P<leak_detection_id>[0-9]+)/details$', views.waterleak_get_leak_detection_details, name = 'waterleak_get_leak_detection_details'),
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/leak_detections/(?P<leak_detection_id>[0-9]+)/edit$', views.waterleak_edit_leak_detection, name = 'waterleak_edit_leak_detection'),
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/leak_detections/(?P<leak_detection_id>[0-9]+)/run$', views.waterleak_run_leak_detection, name = 'waterleak_run_leak_detection'),
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/leak_detections/(?P<leak_detection_id>[0-9]+)/run_identify_leaks$', views.waterleak_run_leak_detection_identify_leaks, name = 'waterleak_run_leak_detection_identify_leaks'),
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/leak_detections/(?P<leak_detection_id>[0-9]+)/get_user_leak_points$', views.waterleak_get_user_leak_points, name = 'waterleak_get_user_leak_points'),
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/leak_detections/(?P<leak_detection_id>[0-9]+)/save_user_leak_points$', views.waterleak_save_user_leak_points, name = 'waterleak_save_user_leak_points'),
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/leak_detections/(?P<leak_detection_id>[0-9]+)/show_leak_points$', views.waterleak_show_leak_points, name = 'waterleak_show_leak_points'),
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/leak_detections/(?P<leak_detection_id>[0-9]+)/show_user_leak_point$', views.waterleak_show_user_leak_point, name = 'waterleak_show_user_leak_point'),
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/leak_detections/(?P<leak_detection_id>[0-9]+)/delete_a_user_leak_point$', views.waterleak_delete_a_user_leak_point, name = 'waterleak_delete_a_user_leak_point'),
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/leak_detections/(?P<leak_detection_id>[0-9]+)/delete_user_leak_points$', views.waterleak_delete_user_leak_points, name = 'waterleak_delete_user_leak_points'),
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/leak_detections/(?P<leak_detection_id>[0-9]+)/edit_user_leak_point$', views.waterleak_edit_user_leak_point, name = 'waterleak_edit_user_leak_point'),#change_visibilty
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/leak_detections/(?P<leak_detection_id>[0-9]+)/download_user_leak_point$', views.waterleak_download_user_leak_point, name = 'waterleak_download_user_leak_point'),
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/leak_detections/(?P<leak_detection_id>[0-9]+)/clone_user_leak_points$', views.waterleak_clone_user_leak_points, name = 'waterleak_clone_user_leak_points'),
    
    
    #TODO: fix this crap
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/leak_detections/(?P<leak_detection_id>[0-9]+)/intermediate/processimageset/(?P<intermediate_process_imageset_id>[0-9]+)/(?P<determine_leak>[\w+]+)/(?P<leak_type>[\w+]+)/(?P<intermediate_raster_type>[\w+]+)/(?P<intermediate_raster_id>[0-9]+)$', views.show_simulation_procimageset_raster_leakdetection, name = 'show_simulation_procimageset_raster_leakdetection'),
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/leak_detections/(?P<leak_detection_id>[0-9]+)/intermediate/processimageset/(?P<intermediate_process_imageset_id>[0-9]+)/(?P<determine_leak>[\w+]+)/(?P<leak_type>[\w+]+)/(?P<intermediate_raster_type>[\w+]+)/(?P<intermediate_raster_id>[0-9]+)/leak_points/show$', views.show_simulation_procimageset_raster_leakdetection_leakpoints, name = 'show_simulation_procimageset_raster_leakdetection_leakpoints'),
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/leak_detections/(?P<leak_detection_id>[0-9]+)/intermediate/processimageset/(?P<intermediate_process_imageset_id>[0-9]+)/(?P<determine_leak>[\w+]+)/(?P<leak_type>[\w+]+)/(?P<intermediate_raster_type>[\w+]+)/(?P<intermediate_raster_id>[0-9]+)/leak_points/download$', views.download_simulation_procimageset_raster_leakdetection_leakpoints, name = 'download_simulation_procimageset_raster_leakdetection_leakpoints'),
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/leak_detections/(?P<leak_detection_id>[0-9]+)/intermediate/processimageset/(?P<intermediate_process_imageset_id>[0-9]+)/(?P<determine_leak>[\w+]+)/(?P<leak_type>[\w+]+)/(?P<intermediate_raster_type>[\w+]+)/(?P<intermediate_raster_id>[0-9]+)/leak_points/(?P<leak_point_id>[0-9]+)/change_visibility$', views.change_simulation_procimageset_raster_leakdetection_leakpoint, name = 'change_simulation_procimageset_raster_leakdetection_leakpoint'),
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/leak_detections/(?P<leak_detection_id>[0-9]+)/intermediate/ucprocessimageset/(?P<intermediate_ucprocess_imageset_id>[0-9]+)/(?P<determine_leak>[\w+]+)/(?P<leak_type>[\w+]+)/(?P<intermediate_raster_type>[\w+]+)/(?P<intermediate_raster_id>[0-9]+)$', views.show_simulation_ucprocimageset_raster_leakdetection, name = 'show_simulation_ucprocimageset_raster_leakdetection'),
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/leak_detections/(?P<leak_detection_id>[0-9]+)/intermediate/ucprocessimageset/(?P<intermediate_ucprocess_imageset_id>[0-9]+)/(?P<determine_leak>[\w+]+)/(?P<leak_type>[\w+]+)/(?P<intermediate_raster_type>[\w+]+)/(?P<intermediate_raster_id>[0-9]+)/leak_points/show$', views.show_simulation_ucprocimageset_raster_leakdetection_leakpoints, name = 'show_simulation_ucprocimageset_raster_leakdetection_leakpoints'),
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/leak_detections/(?P<leak_detection_id>[0-9]+)/intermediate/ucprocessimageset/(?P<intermediate_ucprocess_imageset_id>[0-9]+)/(?P<determine_leak>[\w+]+)/(?P<leak_type>[\w+]+)/(?P<intermediate_raster_type>[\w+]+)/(?P<intermediate_raster_id>[0-9]+)/leak_points/download$', views.download_simulation_ucprocimageset_raster_leakdetection_leakpoints, name = 'download_simulation_ucprocimageset_raster_leakdetection_leakpoints'),
    
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/intermediate/processimageset$', views.waterleak_get_list_imagesets, name = 'waterleak_get_list_imagesets'),
    url(r'^waterleak/leakdetection/rois/(?P<roi_id>[0-9]+)/simulations/(?P<simulation_id>[0-9]+)/intermediate/processimageset/(?P<intermediate_process_imageset_id>[0-9]+)$/indexes', views.waterleak_get_list_imageset_indexes, name = 'waterleak_get_list_imageset_indexes'),
    
    
    #USER REPOSITORY UPLOAD
    url(r'^proxy/intermediate/user_repository/(?P<service_type>[\w+]+)/show$', views.proxy_intermediate_show_user_repository, name = 'proxy_intermediate_show_user_repository'),
    
    url(r'^proxy/intermediate/user_repository/(?P<service_type>[\w+]+)/geometries/upload$', views.proxy_intermediate_upload_user_repository_geometry, name = 'proxy_intermediate_upload_user_repository_geometry'),
    url(r'^proxy/intermediate/user_repository/(?P<service_type>[\w+]+)/geometries/(?P<geometry_id>[0-9]+)$', views.proxy_intermediate_show_user_repository_geometry, name = 'proxy_intermediate_show_user_repository_geometry'),
    url(r'^proxy/intermediate/user_repository/(?P<service_type>[\w+]+)/geometries/(?P<geometry_id>[0-9]+)/delete$', views.proxy_intermediate_delete_user_repository_geometry, name = 'proxy_intermediate_delete_user_repository_geometry'),
    url(r'^proxy/intermediate/user_repository/(?P<service_type>[\w+]+)/geometries/preview$', views.proxy_intermediate_preview_user_repository_geometry, name = 'proxy_intermediate_preview_user_repository_geometry'),

    url(r'^proxy/intermediate/user_repository/(?P<service_type>[\w+]+)/masks/upload$', views.proxy_intermediate_upload_user_repository_mask, name = 'proxy_intermediate_upload_user_repository_mask'),
    url(r'^proxy/intermediate/user_repository/(?P<service_type>[\w+]+)/masks/(?P<mask_id>[0-9]+)/(?P<raster_id>[0-9]+)$', views.proxy_intermediate_show_user_repository_mask, name = 'proxy_intermediate_show_user_repository_mask'),
    url(r'^proxy/intermediate/user_repository/(?P<service_type>[\w+]+)/masks/(?P<mask_id>[0-9]+)/delete$', views.proxy_intermediate_delete_user_repository_mask, name = 'proxy_intermediate_delete_user_repository_mask'),

    url(r'^proxy/intermediate/user_repository/(?P<service_type>[\w+]+)/leaks/upload$', views.proxy_intermediate_upload_user_repository_leak, name = 'proxy_intermediate_upload_user_repository_leak'),
    url(r'^proxy/intermediate/user_repository/(?P<service_type>[\w+]+)/leaks/(?P<leak_id>[0-9]+)$', views.proxy_intermediate_show_user_repository_leak, name = 'proxy_intermediate_show_user_repository_leak'),
    url(r'^proxy/intermediate/user_repository/(?P<service_type>[\w+]+)/leaks/(?P<leak_id>[0-9]+)/delete$', views.proxy_intermediate_delete_user_repository_leak, name = 'proxy_intermediate_delete_user_repository_leak'),

    url(r'^proxy/intermediate/user_repository/(?P<service_type>[\w+]+)/imagesets$', views.proxy_intermediate_list_user_repository_imageset, name = 'proxy_intermediate_list_user_repository_imageset'),
    url(r'^proxy/intermediate/user_repository/(?P<service_type>[\w+]+)/imagesets/upload$', views.proxy_intermediate_upload_user_repository_imageset, name = 'proxy_intermediate_upload_user_repository_imageset'),
    url(r'^proxy/intermediate/user_repository/(?P<service_type>[\w+]+)/imagesets/(?P<imageset_id>[0-9]+)$', views.proxy_intermediate_show_user_repository_imageset, name = 'proxy_intermediate_show_user_repository_imageset'),
    url(r'^proxy/intermediate/user_repository/(?P<service_type>[\w+]+)/imagesets/(?P<imageset_id>[0-9]+)/show_thumbnail$', views.proxy_intermediate_show_thumbnail_user_repository_imageset, name = 'proxy_intermediate_show_thumbnail_user_repository_imageset'),
    url(r'^proxy/intermediate/user_repository/(?P<service_type>[\w+]+)/imagesets/(?P<imageset_id>[0-9]+)/edit$', views.proxy_intermediate_edit_user_repository_imageset, name = 'proxy_intermediate_edit_user_repository_imageset'),
    url(r'^proxy/intermediate/user_repository/(?P<service_type>[\w+]+)/imagesets/(?P<imageset_id>[0-9]+)/delete$', views.proxy_intermediate_delete_user_repository_imageset, name = 'proxy_intermediate_delete_user_repository_imageset'),

    
    
    
    url(r'^proxy/intermediate/endpoint/(?P<intermediate_path>.*)$', views.proxy_get_intermediate_raster_endpoint, name = 'proxy_get_intermediate_raster_endpoint'),
    url(r'^proxy/intermediate/(?P<intermediate_path>.*)$', views.proxy_get_intermediate_procimageset_raster, name = 'proxy_get_intermediate_procimageset_raster'),
    
    url(r'^data/imagery.json$', views.get_satellite_imagery, name = 'get_satellite_imagery'),
    url(r'^data/thumbnail/(?P<uuid>[0-9a-f-]+)/show$', views.proxy_get_imageset_thumbnail, name = 'proxy_get_imageset_thumbnail'),
    url(r'^data/esa_imagery.json$', views.get_satellite_imagery_from_esa, name = 'get_satellite_imagery_from_esa'),  
    url(r'^data/probe_sea_tides$', views.probe_sea_tides, name='probe_sea_tides'),
    url(r'^data/upload_sea_tides$', views.upload_sea_tides, name='upload_sea_tides'),
    url(r'^data/generate_topography_roi_simulation$', views.generate_topography_roi_simulation, name='generate_topography_roi_simulation'),
    
]